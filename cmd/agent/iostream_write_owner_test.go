package main

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestIOStreamWriteOwner_SerializesSendAndClose(t *testing.T) {
	// Given
	streamContext, cancelStreamContext := context.WithCancel(context.Background())
	stream := newIOStreamFixture(streamContext, streamCallAllowance{send: 1, closeSend: 1})
	owner := newIOStreamWriteOwner(stream, func(error) { cancelStreamContext() })
	sendExited := make(chan error, 1)
	go func() { sendExited <- owner.Send(&pb.IOStreamData{Data: []byte("business")}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	graceContext, cancelGrace := context.WithCancel(context.Background())
	shutdownExited := make(chan ioStreamWriteShutdownResult, 1)
	go func() { shutdownExited <- owner.Shutdown(graceContext, context.Canceled) }()

	// When
	cancelGrace()
	result := awaitStreamOperationResult(t, shutdownExited)

	// Then
	if !result.Forced || !errors.Is(result.Cause, context.Canceled) {
		t.Fatalf("shutdown result = %+v, want forced context.Canceled", result)
	}
	if err := awaitStreamOperationResult(t, sendExited); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send error = %v, want context.Canceled", err)
	}
	observation := stream.observe()
	assertStreamEvents(t, observation.events, []string{"send:start:1", "send:canceled:1", "close_send:start:1", "close_send:canceled:1"})
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("writes: max=%d close=%d, want max=1 close=1", observation.maxWriteInFlight, observation.closeSendCount)
	}
}

func TestIOStreamWriteOwner_StopsAndJoinsKeepalive(t *testing.T) {
	// Given
	stream := newIOStreamFixture(context.Background(), streamCallAllowance{send: 1, closeSend: 1})
	owner := newIOStreamWriteOwner(stream, func(error) {})
	if err := owner.StartKeepalive(time.Nanosecond); err != nil {
		t.Fatalf("StartKeepalive returned error: %v", err)
	}
	stream.waitWriteEntered(t, streamWriteSend)

	// When
	keepaliveDone := owner.StopKeepalive()
	if secondDone := owner.StopKeepalive(); keepaliveDone != secondDone {
		t.Fatal("idempotent keepalive stop returned a different join channel")
	}
	select {
	case <-keepaliveDone:
		t.Fatal("keepalive stop signal was treated as a completed goroutine join")
	default:
	}
	stream.releaseWrite(streamWriteSend, nil)
	awaitStreamSignal(t, keepaliveDone, "keepalive join")
	shutdownExited := make(chan ioStreamWriteShutdownResult, 1)
	go func() { shutdownExited <- owner.Shutdown(context.Background(), context.Canceled) }()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	result := awaitStreamOperationResult(t, shutdownExited)

	// Then
	if result.Err != nil || result.Forced {
		t.Fatalf("shutdown result = %+v, want graceful success", result)
	}
	observation := stream.observe()
	assertStreamEvents(t, observation.events, []string{"send:start:1", "send:end:1", "close_send:start:1", "close_send:end:1"})
	if observation.maxWriteInFlight != 1 {
		t.Fatalf("max write concurrency = %d, want 1", observation.maxWriteInFlight)
	}
}

func TestIOStreamWriteOwner_ClosesOnce(t *testing.T) {
	// Given
	stream := newIOStreamFixture(context.Background(), streamCallAllowance{closeSend: 1})
	owner := newIOStreamWriteOwner(stream, func(error) {})
	firstExited := make(chan ioStreamWriteShutdownResult, 1)
	go func() { firstExited <- owner.Shutdown(context.Background(), context.Canceled) }()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	secondExited := make(chan ioStreamWriteShutdownResult, 1)
	go func() { secondExited <- owner.Shutdown(context.Background(), errors.New("second shutdown")) }()
	select {
	case operation := <-stream.writeEntered:
		t.Fatalf("concurrent shutdown entered a duplicate write: %q", operation)
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

func TestIOStreamWriteOwner_RejectsSendAfterClose(t *testing.T) {
	// Given
	stream := newIOStreamFixture(context.Background(), streamCallAllowance{closeSend: 1})
	owner := newIOStreamWriteOwner(stream, func(error) {})
	shutdownExited := make(chan ioStreamWriteShutdownResult, 1)
	go func() { shutdownExited <- owner.Shutdown(context.Background(), context.Canceled) }()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	result := awaitStreamOperationResult(t, shutdownExited)

	// When
	err := owner.Send(&pb.IOStreamData{Data: []byte("late")})

	// Then
	if result.Err != nil || !errors.Is(err, errIOStreamWriteClosed) {
		t.Fatalf("shutdown=%+v late Send error=%v, want closed", result, err)
	}
	observation := stream.observe()
	if len(observation.unexpectedCalls) != 0 {
		t.Fatalf("late Send reached stream: %v", observation.unexpectedCalls)
	}
}

func TestIOStreamWriteOwner_PropagatesFirstError(t *testing.T) {
	t.Run("Send error precedes CloseSend error", func(t *testing.T) {
		// Given
		errSend := errors.New("send failed")
		errClose := errors.New("close failed")
		stream := newIOStreamFixture(context.Background(), streamCallAllowance{send: 1, closeSend: 1})
		cancelCalls := make(chan error, 2)
		owner := newIOStreamWriteOwner(stream, func(cause error) { cancelCalls <- cause })
		firstSendExited := make(chan error, 1)
		go func() { firstSendExited <- owner.Send(&pb.IOStreamData{Data: []byte("first")}) }()
		stream.waitWriteEntered(t, streamWriteSend)
		queuedSendExited := make(chan error, 1)
		go func() { queuedSendExited <- owner.Send(&pb.IOStreamData{Data: []byte("queued")}) }()

		// When
		stream.releaseWrite(streamWriteSend, errSend)
		if err := awaitStreamOperationResult(t, firstSendExited); !errors.Is(err, errSend) {
			t.Fatalf("first Send error = %v, want %v", err, errSend)
		}
		if err := awaitStreamOperationResult(t, queuedSendExited); !errors.Is(err, errIOStreamWriteClosed) || !errors.Is(err, errSend) {
			t.Fatalf("queued Send error = %v, want closed plus first Send error", err)
		}
		shutdownExited := make(chan ioStreamWriteShutdownResult, 1)
		go func() { shutdownExited <- owner.Shutdown(context.Background(), context.Canceled) }()
		stream.waitWriteEntered(t, streamWriteCloseSend)
		stream.releaseWrite(streamWriteCloseSend, errClose)
		result := awaitStreamOperationResult(t, shutdownExited)

		// Then
		if !errors.Is(result.Err, errSend) || errors.Is(result.Err, errClose) {
			t.Fatalf("shutdown error = %v, want first Send error only", result.Err)
		}
		if cause := awaitStreamOperationResult(t, cancelCalls); !errors.Is(cause, errSend) {
			t.Fatalf("cancel cause = %v, want %v", cause, errSend)
		}
		select {
		case cause := <-cancelCalls:
			t.Fatalf("stream canceled more than once: %v", cause)
		default:
		}
		observation := stream.observe()
		if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 || len(observation.unexpectedCalls) != 0 {
			t.Fatalf("write observation = %+v", observation)
		}
	})

	t.Run("CloseSend error is retained when no Send failed", func(t *testing.T) {
		// Given
		errClose := errors.New("close failed")
		stream := newIOStreamFixture(context.Background(), streamCallAllowance{closeSend: 1})
		cancelCalls := make(chan error, 1)
		owner := newIOStreamWriteOwner(stream, func(cause error) { cancelCalls <- cause })
		shutdownExited := make(chan ioStreamWriteShutdownResult, 1)
		go func() { shutdownExited <- owner.Shutdown(context.Background(), context.Canceled) }()
		stream.waitWriteEntered(t, streamWriteCloseSend)

		// When
		stream.releaseWrite(streamWriteCloseSend, errClose)
		result := awaitStreamOperationResult(t, shutdownExited)

		// Then
		if !errors.Is(result.Err, errClose) {
			t.Fatalf("shutdown error = %v, want %v", result.Err, errClose)
		}
		if cause := awaitStreamOperationResult(t, cancelCalls); !errors.Is(cause, errClose) {
			t.Fatalf("cancel cause = %v, want %v", cause, errClose)
		}
		if err := owner.Send(&pb.IOStreamData{}); !errors.Is(err, errIOStreamWriteClosed) || !errors.Is(err, errClose) {
			t.Fatalf("late Send error = %v, want closed plus CloseSend error", err)
		}
	})
}
