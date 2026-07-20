package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
)

func TestTerminalWire_InputResizeAndUnknownTagsUseInjectedPTY(t *testing.T) {
	// Given
	originalConfig := agentConfig
	originalHandlerFactory := terminalHandlerForTask
	restoreRuntimeConfigSnapshot(t)
	t.Cleanup(func() {
		agentConfig = originalConfig
		terminalHandlerForTask = originalHandlerFactory
	})
	agentConfig = model.AgentConfig{}
	publishRuntimeConfig(agentConfig)
	stream := &terminalTestStream{}
	tty := newTerminalTestPTY()
	terminalOutput := []byte("terminal-output")
	tty.reads <- terminalPTYRead{data: terminalOutput}
	outputSent := make(chan struct{})
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, terminalOutput) {
			close(outputSent)
		}
		return nil
	}
	incoming := [][]byte{
		append([]byte{0}, []byte("literal-input")...),
		[]byte{1, '{', '"', 'C', 'o', 'l', 's', '"', ':', '3', '1', ',', '"', 'R', 'o', 'w', 's', '"', ':', '1', '7', '}'},
		append([]byte{2}, []byte("ignored-input")...),
	}
	nextIncoming := 0
	stream.recvHook = func() (*pb.IOStreamData, error) {
		if nextIncoming < len(incoming) {
			data := incoming[nextIncoming]
			nextIncoming++
			return &pb.IOStreamData{Data: data}, nil
		}
		<-outputSent
		return nil, io.EOF
	}
	// Keep protocol assertions independent from host PTY behavior on every platform.
	terminalHandlerForTask = func() terminalHandler {
		return terminalHandler{
			openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
				stream.ctx = ctx
				return stream, nil
			},
			startPTY:          func() (pty.IPty, error) { return tty, nil },
			startKeepalive:    func(*ioStreamWriteOwner, time.Duration) error { return nil },
			keepaliveInterval: time.Hour,
			shutdownTimeout:   100 * time.Millisecond,
		}
	}
	handlerDone := make(chan struct{})

	// When
	go func() {
		handleTerminalTask(&pb.Task{Data: `{"StreamID":"term-tag"}`})
		close(handlerDone)
	}()
	awaitStreamSignal(t, handlerDone, "terminal wire handler completion")

	// Then
	frames, maxInFlight, closeCount, recvCount := stream.observation()
	wantAttach := terminalAttachFrame("term-tag")
	if len(frames) != 2 || !bytes.Equal(frames[0], wantAttach) || !bytes.Equal(frames[1], terminalOutput) {
		t.Fatalf("Terminal frames = %q, want attach followed by PTY output", frames)
	}
	if maxInFlight != 1 || closeCount != 1 || recvCount != 4 || tty.closes() != 1 {
		t.Fatalf("Terminal lifecycle: max_writes=%d close_send=%d recv=%d pty_close=%d, want 1/1/4/1", maxInFlight, closeCount, recvCount, tty.closes())
	}
	tty.mu.Lock()
	defer tty.mu.Unlock()
	if len(tty.writes) != 1 || !bytes.Equal(tty.writes[0], []byte("literal-input")) {
		t.Fatalf("Terminal input writes = %q, want literal tag 0 payload", tty.writes)
	}
	if len(tty.sizes) != 1 || tty.sizes[0] != (terminalWindowSize{Cols: 31, Rows: 17}) {
		t.Fatalf("Terminal resize calls = %+v, want cols=31 rows=17", tty.sizes)
	}
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
