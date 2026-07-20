package main

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

type terminalWireScenario struct {
	streamID      string
	incoming      [][]byte
	waitForOutput []byte
}

type terminalWireStream struct {
	*iostreamWireStream
	incoming       [][]byte
	waitForOutput  []byte
	outputObserved chan struct{}
	observeOnce    sync.Once
	closeCount     atomic.Int32
}

func (s *terminalWireStream) Send(data *pb.IOStreamData) error {
	if err := s.iostreamWireStream.Send(data); err != nil {
		return err
	}
	if bytes.Contains(data.GetData(), s.waitForOutput) {
		s.observeOnce.Do(func() { close(s.outputObserved) })
	}
	return nil
}

func (s *terminalWireStream) Recv() (*pb.IOStreamData, error) {
	if len(s.incoming) > 0 {
		data := s.incoming[0]
		s.incoming = s.incoming[1:]
		return &pb.IOStreamData{Data: data}, nil
	}
	select {
	case <-s.outputObserved:
		return nil, io.EOF
	case <-time.After(5 * time.Second):
		return nil, io.ErrNoProgress
	}
}

func (s *terminalWireStream) CloseSend() error {
	s.closeCount.Add(1)
	return nil
}

func runTerminalWireScenario(t *testing.T, scenario terminalWireScenario) [][]byte {
	t.Helper()
	originalClient, originalConfig := client, agentConfig
	stream := &terminalWireStream{
		iostreamWireStream: &iostreamWireStream{},
		incoming:           scenario.incoming,
		waitForOutput:      scenario.waitForOutput,
		outputObserved:     make(chan struct{}),
	}
	client = &iostreamWireClient{stream: stream}
	agentConfig = model.AgentConfig{}
	t.Cleanup(func() {
		client, agentConfig = originalClient, originalConfig
	})

	handlerDone := make(chan struct{})
	go func() {
		defer close(handlerDone)
		handleTerminalTask(&pb.Task{Data: `{"StreamID":"` + scenario.streamID + `"}`})
	}()
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Terminal handler goroutine did not complete before deadline")
	}
	if closeCount := stream.closeCount.Load(); closeCount != 1 {
		t.Fatalf("Terminal CloseSend count = %d, want 1", closeCount)
	}
	return stream.frames()
}

func TestTerminalWire_InputAndResizeTagsDriveTerminal(t *testing.T) {
	command := []byte{0x70, 0x72, 0x69, 0x6e, 0x74, 0x66, 0x20, 0x54, 0x45, 0x52, 0x4d, 0x49, 0x4e, 0x41, 0x4c, 0x5f, 0x54, 0x41, 0x47, 0x5f, 0x4f, 0x4b, 0x5c, 0x6e, 0x0a}
	validInput := append([]byte{0x00}, command...)
	mutatedInput := append([]byte{0x02}, command...)
	wantAttach := []byte{0xff, 0x05, 0xff, 0x05, 0x74, 0x65, 0x72, 0x6d, 0x2d, 0x74, 0x61, 0x67}

	validFrames := runTerminalWireScenario(t, terminalWireScenario{
		streamID:      "term-tag",
		incoming:      [][]byte{validInput},
		waitForOutput: []byte("TERMINAL_TAG_OK"),
	})
	if len(validFrames) < 2 || !bytes.Equal(validFrames[0], wantAttach) {
		t.Fatalf("Terminal valid-tag attach or output changed: frames=%q", validFrames)
	}
	validOutputObserved := false
	for _, frame := range validFrames[1:] {
		validOutputObserved = validOutputObserved || bytes.Contains(frame, []byte("TERMINAL_TAG_OK"))
	}
	if !validOutputObserved {
		t.Fatalf("Terminal handler did not execute literal tag 0 input: frames=%q", validFrames)
	}

	mutatedFrames := runTerminalWireScenario(t, terminalWireScenario{
		streamID: "term-tag",
		incoming: [][]byte{
			mutatedInput,
			{0x01, 0x7b, 0x22, 0x43, 0x6f, 0x6c, 0x73, 0x22, 0x3a, 0x33, 0x31, 0x2c, 0x22, 0x52, 0x6f, 0x77, 0x73, 0x22, 0x3a, 0x31, 0x37, 0x7d},
			{0x00, 0x73, 0x74, 0x74, 0x79, 0x20, 0x73, 0x69, 0x7a, 0x65, 0x0a},
		},
		waitForOutput: []byte("17 31"),
	})
	if len(mutatedFrames) < 2 || !bytes.Equal(mutatedFrames[0], wantAttach) {
		t.Fatalf("Terminal mutated-tag attach or control output changed: frames=%q", mutatedFrames)
	}
	resizeOutputObserved := false
	for _, frame := range mutatedFrames[1:] {
		if bytes.Contains(frame, []byte("TERMINAL_TAG_OK")) {
			t.Fatalf("Terminal handler accepted one-byte tag mutation: frames=%q", mutatedFrames)
		}
		resizeOutputObserved = resizeOutputObserved || bytes.Contains(frame, []byte("17 31"))
	}
	if !resizeOutputObserved {
		t.Fatalf("Terminal handler did not execute literal resize and input tags: frames=%q", mutatedFrames)
	}
	t.Logf("Terminal valid frames=%x", validFrames)
	t.Logf("Terminal mutated-tag/resize frames=%x", mutatedFrames)
}

func TestTerminalWire_KeepAliveGoroutineReportsCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	stream := &iostreamWireStream{}

	go func() {
		defer close(done)
		ioStreamKeepAlive(ctx, stream)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Terminal keepalive goroutine reached cancellation without an explicit completion signal")
	}
}
