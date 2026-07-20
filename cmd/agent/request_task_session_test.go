package main

import (
	"context"
	"errors"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

func TestRequestTaskSession_SerializesBlockedSendAndClose(t *testing.T) {
	// Given
	streamContext, cancelStream := context.WithCancelCause(context.Background())
	stream := newRequestTaskStreamFixture(streamContext, streamCallAllowance{send: 1, closeSend: 1})
	session := newRequestTaskSession(stream, cancelStream)
	sendExited := make(chan error, 1)
	go func() { sendExited <- session.Send(&pb.TaskResult{Id: 1}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	shutdownExited := make(chan requestTaskShutdownResult, 1)
	go func() {
		shutdownExited <- session.shutdown(context.Background())
	}()

	// When
	select {
	case operation := <-stream.writeEntered:
		t.Fatalf("CloseSend overlapped blocked result Send: %q", operation)
	default:
	}
	stream.releaseWrite(streamWriteSend, nil)
	if err := awaitStreamOperationResult(t, sendExited); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	result := awaitStreamOperationResult(t, shutdownExited)

	// Then
	if result.Err != nil || result.Forced {
		t.Fatalf("shutdown result = %+v, want graceful success", result)
	}
	observation := stream.observe()
	assertStreamEvents(t, observation.events, []string{"send:start:1", "send:end:1", "close_send:start:1", "close_send:end:1"})
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("writes: max=%d close=%d, want max=1 close=1", observation.maxWriteInFlight, observation.closeSendCount)
	}
}

func TestRequestTaskSession_RejectsSendAfterClose(t *testing.T) {
	// Given
	stream := newRequestTaskStreamFixture(context.Background(), streamCallAllowance{closeSend: 1})
	session := newRequestTaskSession(stream, func(error) {})
	shutdownExited := make(chan requestTaskShutdownResult, 1)
	go func() {
		shutdownExited <- session.shutdown(context.Background())
	}()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	result := awaitStreamOperationResult(t, shutdownExited)

	// When
	err := session.Send(&pb.TaskResult{Id: 2})

	// Then
	if result.Err != nil || !errors.Is(err, errRequestTaskSessionClosed) {
		t.Fatalf("shutdown=%+v late Send error=%v, want closed", result, err)
	}
	if observation := stream.observe(); len(observation.unexpectedCalls) != 0 {
		t.Fatalf("late Send reached stream: %v", observation.unexpectedCalls)
	}
}

func TestRequestTaskSession_ClosesOnce(t *testing.T) {
	// Given
	stream := newRequestTaskStreamFixture(context.Background(), streamCallAllowance{closeSend: 1})
	session := newRequestTaskSession(stream, func(error) {})
	firstExited := make(chan requestTaskShutdownResult, 1)
	secondExited := make(chan requestTaskShutdownResult, 1)
	go func() {
		firstExited <- session.shutdown(context.Background())
	}()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	go func() {
		secondExited <- session.shutdown(context.Background())
	}()
	select {
	case operation := <-stream.writeEntered:
		t.Fatalf("concurrent shutdown entered duplicate write: %q", operation)
	default:
	}

	// When
	stream.releaseWrite(streamWriteCloseSend, nil)
	first := awaitStreamOperationResult(t, firstExited)
	second := awaitStreamOperationResult(t, secondExited)

	// Then
	if first.Err != nil || second.Err != nil || first.Forced || second.Forced {
		t.Fatalf("shutdown results: first=%+v second=%+v", first, second)
	}
	observation := stream.observe()
	if observation.closeSendCount != 1 || len(observation.unexpectedCalls) != 0 {
		t.Fatalf("close observation = %+v, want exactly one expected CloseSend", observation)
	}
}

func TestRequestTaskSession_FirstSendErrorCancelsOnce(t *testing.T) {
	// Given
	errSend := errors.New("result send failed")
	stream := newRequestTaskStreamFixture(context.Background(), streamCallAllowance{send: 1, closeSend: 1})
	cancelCalls := make(chan error, 2)
	session := newRequestTaskSession(stream, func(cause error) { cancelCalls <- cause })
	firstExited := make(chan error, 1)
	go func() { firstExited <- session.Send(&pb.TaskResult{Id: 3}) }()
	stream.waitWriteEntered(t, streamWriteSend)

	// When
	stream.releaseWrite(streamWriteSend, errSend)
	if err := awaitStreamOperationResult(t, firstExited); !errors.Is(err, errSend) {
		t.Fatalf("first Send error = %v, want %v", err, errSend)
	}
	lateErr := session.Send(&pb.TaskResult{Id: 4})
	shutdownExited := make(chan requestTaskShutdownResult, 1)
	go func() {
		shutdownExited <- session.shutdown(context.Background())
	}()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, errors.New("later close error"))
	result := awaitStreamOperationResult(t, shutdownExited)

	// Then
	if !errors.Is(lateErr, errRequestTaskSessionClosed) || !errors.Is(lateErr, errSend) {
		t.Fatalf("late Send error = %v, want closed plus first error", lateErr)
	}
	if !errors.Is(result.Err, errSend) {
		t.Fatalf("shutdown error = %v, want first Send error", result.Err)
	}
	if cause := awaitStreamOperationResult(t, cancelCalls); !errors.Is(cause, errSend) {
		t.Fatalf("cancel cause = %v, want %v", cause, errSend)
	}
	select {
	case cause := <-cancelCalls:
		t.Fatalf("stream canceled more than once: %v", cause)
	default:
	}
}

func TestRequestTaskSession_ForcedShutdownUnblocksSendBeforeClose(t *testing.T) {
	// Given
	streamContext, cancelStreamContext := context.WithCancelCause(context.Background())
	stream := newRequestTaskStreamFixture(streamContext, streamCallAllowance{send: 1, closeSend: 1})
	session := newRequestTaskSession(stream, cancelStreamContext)
	sendExited := make(chan error, 1)
	go func() { sendExited <- session.Send(&pb.TaskResult{Id: 5}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	graceContext, cancelGrace := context.WithCancelCause(context.Background())
	shutdownExited := make(chan requestTaskShutdownResult, 1)
	go func() {
		shutdownExited <- session.shutdown(graceContext)
	}()

	// When
	forcedCause := errors.New("grace expired")
	cancelGrace(forcedCause)
	result := awaitStreamOperationResult(t, shutdownExited)

	// Then
	if !result.Forced || !errors.Is(result.Cause, forcedCause) {
		t.Fatalf("shutdown result = %+v, want forced cause %v", result, forcedCause)
	}
	if err := awaitStreamOperationResult(t, sendExited); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked Send error = %v, want context.Canceled", err)
	}
	observation := stream.observe()
	assertStreamEvents(t, observation.events, []string{"send:start:1", "send:canceled:1", "close_send:start:1", "close_send:canceled:1"})
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("writes: max=%d close=%d, want max=1 close=1", observation.maxWriteInFlight, observation.closeSendCount)
	}
}
