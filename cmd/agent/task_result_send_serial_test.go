package main

import (
	"context"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

func TestRequestTaskSession_SerializesConcurrentResultSends(t *testing.T) {
	// Given
	stream := newRequestTaskStreamFixture(context.Background(), streamCallAllowance{send: 2})
	session := newRequestTaskSession(stream, func(error) {})
	firstExited := make(chan error, 1)
	secondExited := make(chan error, 1)
	go func() { firstExited <- session.Send(&pb.TaskResult{Id: 1}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	secondStarted := make(chan struct{})
	go func() {
		close(secondStarted)
		secondExited <- session.Send(&pb.TaskResult{Id: 2})
	}()
	awaitStreamSignal(t, secondStarted, "second result Send start")

	// When
	stream.releaseWrite(streamWriteSend, nil)
	stream.waitWriteEntered(t, streamWriteSend)
	stream.releaseWrite(streamWriteSend, nil)

	// Then
	if err := awaitStreamOperationResult(t, firstExited); err != nil {
		t.Fatalf("first Send returned error: %v", err)
	}
	if err := awaitStreamOperationResult(t, secondExited); err != nil {
		t.Fatalf("second Send returned error: %v", err)
	}
	observation := stream.observe()
	if observation.maxWriteInFlight != 1 {
		t.Fatalf("result Send max concurrency = %d, want 1", observation.maxWriteInFlight)
	}
	assertStreamEvents(t, observation.events, []string{
		"send:start:1", "send:end:1", "send:start:2", "send:end:2",
	})
}
