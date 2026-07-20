package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
)

func TestTerminalShutdown_KeepaliveStartFailureDoesNotJoinUnstartedWorkers(t *testing.T) {
	// Given
	keepaliveErr := errors.New("keepalive start failed")
	tty := newTerminalTestPTY()
	stream := &terminalTestStream{}
	handler := terminalHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			stream.ctx = ctx
			return stream, nil
		},
		startPTY: func() (pty.IPty, error) { return tty, nil },
		startKeepalive: func(*ioStreamWriteOwner, time.Duration) error {
			return keepaliveErr
		},
		keepaliveInterval: time.Hour,
		shutdownTimeout:   100 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() {
		handler.run(context.Background(), taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"keepalive-failure"}`})
		close(done)
	}()

	// When
	awaitStreamSignal(t, done, "keepalive-start failure cleanup")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 0 || tty.closes() != 1 {
		t.Fatalf("keepalive failure cleanup: max=%d close=%d recv=%d pty_close=%d", maxInFlight, closeCount, recvCount, tty.closes())
	}
	if !errors.Is(context.Cause(stream.ctx), keepaliveErr) {
		t.Fatalf("stream cancel cause = %v, want %v", context.Cause(stream.ctx), keepaliveErr)
	}
}

func TestTerminalShutdown_PTYCloseErrorStillReleasesReadAndJoinsProducer(t *testing.T) {
	// Given
	closeErr := errors.New("pty close failed")
	tty := newTerminalTestPTY()
	tty.closeErr = closeErr
	stream := &terminalTestStream{recvHook: func() (*pb.IOStreamData, error) {
		return nil, errors.New("remote closed")
	}}

	// When
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            context.Background(),
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, done, "PTY Close error cleanup")

	// Then
	awaitStreamSignal(t, tty.readDone, "PTY producer after Close error")
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("PTY Close error cleanup: max=%d close=%d recv=%d pty_close=%d", maxInFlight, closeCount, recvCount, tty.closes())
	}
}
