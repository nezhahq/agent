package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

func TestGRPCGracefulClose_FsTransferClosesBeforePeerTerminal(t *testing.T) {
	// Given
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, events *grpcTCPIOObservation) error {
		if err := grpcTCPDrainIOStream(stream, events.frames); err != nil {
			return err
		}
		stream.SetTrailer(metadata.Pairs("x-grpc-lifecycle", "fs-ok"))
		return nil
	})
	originalClient := client
	client = fixture.client
	t.Cleanup(func() { client = originalClient })
	done := make(chan struct{})
	task := &pb.Task{Data: `{"stream_id":"fs-tcp","op":"invalid","path":"/unused"}`}

	// When
	go func() {
		handleFsTransferTaskWithConfig(context.Background(), taskFeatureGates{}, task)
		close(done)
	}()

	// Then
	receiveGRPCTCPFrame(t, observation.frames, append([]byte{0xff, 0x05, 0xff, 0x05}, []byte("fs-tcp")...))
	frame := awaitStreamOperationResult(t, observation.frames)
	if len(frame) < 4 || string(frame[:4]) != "NZTE" {
		t.Fatalf("fs.transfer terminal frame = %x, want NZTE", frame)
	}
	requireGRPCTCPNormalReturn(t, observation.returned)
	awaitStreamSignal(t, done, "fs.transfer tcp completion")
}

func TestGRPCStreamLifecycle_TerminalUsesPTYAndJoinsProducer(t *testing.T) {
	// Given
	input := []byte("terminal-input")
	output := []byte("terminal-output")
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, events *grpcTCPIOObservation) error {
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		if err := stream.Send(&pb.IOStreamData{Data: append([]byte{0}, input...)}); err != nil {
			return err
		}
		if err := stream.Send(&pb.IOStreamData{Data: []byte{1, '{', '"', 'C', 'o', 'l', 's', '"', ':', '9', '0', ',', '"', 'R', 'o', 'w', 's', '"', ':', '3', '0', '}'}}); err != nil {
			return err
		}
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		return nil
	})
	tty := newTerminalTestPTY()
	tty.reads <- terminalPTYRead{data: output}
	handler := terminalHandler{
		openStream:        openGRPCTCPStream(fixture.client),
		startPTY:          func() (pty.IPty, error) { return tty, nil },
		startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
		keepaliveInterval: time.Hour,
		shutdownTimeout:   streamFixtureDeadline,
	}
	done := make(chan struct{})

	// When
	go func() {
		handler.run(context.Background(), taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"terminal-tcp"}`})
		close(done)
	}()

	// Then
	receiveGRPCTCPFrame(t, observation.frames, terminalAttachFrame("terminal-tcp"))
	receiveGRPCTCPFrame(t, observation.frames, output)
	requireGRPCTCPNormalReturn(t, observation.returned)
	awaitStreamSignal(t, done, "terminal tcp completion")
	tty.mu.Lock()
	writes := append([][]byte(nil), tty.writes...)
	sizes := append([]terminalWindowSize(nil), tty.sizes...)
	tty.mu.Unlock()
	if len(writes) != 1 || string(writes[0]) != string(input) {
		t.Fatalf("terminal PTY writes = %q, want %q", writes, input)
	}
	if len(sizes) != 1 || sizes[0].Cols != 90 || sizes[0].Rows != 30 {
		t.Fatalf("terminal sizes = %+v, want 90x30", sizes)
	}
	if tty.closes() != 1 {
		t.Fatalf("terminal PTY close count = %d, want 1", tty.closes())
	}
}

func TestGRPCCancellation_TerminalParentCancelEndsBoundedly(t *testing.T) {
	// Given
	attachReceived := make(chan struct{}, 1)
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, _ *grpcTCPIOObservation) error {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		wantAttach := terminalAttachFrame("terminal-cancel")
		if !bytes.Equal(message.GetData(), wantAttach) {
			return fmt.Errorf("terminal attach = %x, want %x", message.GetData(), wantAttach)
		}
		attachReceived <- struct{}{}
		<-stream.Context().Done()
		return stream.Context().Err()
	})
	parent, cancelParent := context.WithCancel(context.Background())
	session := newConnectionSession(parent)
	tty := newTerminalTestPTY()
	handler := terminalHandler{
		openStream:        openGRPCTCPStream(fixture.client),
		startPTY:          func() (pty.IPty, error) { return tty, nil },
		startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
		keepaliveInterval: time.Hour,
		shutdownTimeout:   streamFixtureDeadline,
	}
	done := make(chan struct{})
	if !session.startLongLivedStreamTask(func(context.Context) {
		handler.run(parent, taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"terminal-cancel"}`})
		close(done)
	}) {
		t.Fatal("terminal long-lived task registration rejected")
	}
	awaitStreamSignal(t, attachReceived, "terminal attach received")
	awaitStreamSignal(t, tty.readEntered, "terminal PTY producer read")

	// When
	cancelParent()

	// Then
	awaitStreamSignal(t, done, "terminal parent cancellation")
	if err := awaitStreamOperationResult(t, observation.returned); !errors.Is(err, context.Canceled) {
		t.Fatalf("terminal server return = %v, want context.Canceled", err)
	}
	if tty.closes() != 1 {
		t.Fatalf("terminal canceled PTY close count = %d, want 1", tty.closes())
	}
	session.longLivedStreamTasks.wait()
	if session.longLivedStreamTasks.activeCount() != 0 {
		t.Fatalf("terminal active registry = %d, want 0", session.longLivedStreamTasks.activeCount())
	}
}

func TestGRPCCancellation_FsTransferParentCancelEndsBoundedly(t *testing.T) {
	// Given
	started := make(chan struct{}, 1)
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, events *grpcTCPIOObservation) error {
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		started <- struct{}{}
		<-stream.Context().Done()
		return stream.Context().Err()
	})
	originalClient := client
	client = fixture.client
	t.Cleanup(func() { client = originalClient })
	parent, cancelParent := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		handleFsTransferTaskWithConfig(parent, taskFeatureGates{}, &pb.Task{Data: `{"stream_id":"fs-cancel","op":"invalid","path":"/unused"}`})
		close(done)
	}()
	receiveGRPCTCPFrame(t, observation.frames, append([]byte{0xff, 0x05, 0xff, 0x05}, []byte("fs-cancel")...))
	awaitStreamSignal(t, started, "fs.transfer cancel server start")

	// When
	cancelParent()

	// Then
	awaitStreamSignal(t, done, "fs.transfer parent cancellation")
	if err := awaitStreamOperationResult(t, observation.returned); !errors.Is(err, context.Canceled) {
		t.Fatalf("fs.transfer server return = %v, want context.Canceled", err)
	}
}

var _ = io.EOF
