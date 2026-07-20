package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
)

func TestTerminalSendFailure_AttachUsesOwnerCloseOnceWithoutStartingPTY(t *testing.T) {
	// Given
	sendErr := errors.New("attach send failed")
	stream := &terminalTestStream{sendHook: func([]byte) error { return sendErr }}
	ptyStarted := false
	handler := terminalHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			stream.ctx = ctx
			return stream, nil
		},
		startPTY: func() (pty.IPty, error) {
			ptyStarted = true
			return newTerminalTestPTY(), nil
		},
		startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
		keepaliveInterval: time.Hour,
		shutdownTimeout:   100 * time.Millisecond,
	}

	// When
	handler.run(context.Background(), taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"attach-failure"}`})

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if ptyStarted || maxInFlight != 1 || closeCount != 1 || recvCount != 0 {
		t.Fatalf("attach failure: pty_started=%t max=%d close=%d recv=%d", ptyStarted, maxInFlight, closeCount, recvCount)
	}
	if !errors.Is(context.Cause(stream.ctx), sendErr) {
		t.Fatalf("stream cancel cause = %v, want %v", context.Cause(stream.ctx), sendErr)
	}
}
