package main

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestIOStreamWriteOwner_CloseSendAfterQuiescenceJoinsBlockedBusinessSend(t *testing.T) {
	// Given
	stream := newIOStreamFixture(context.Background(), streamCallAllowance{send: 1, closeSend: 1})
	owner := newIOStreamWriteOwner(stream, func(error) {})
	sendExited := make(chan error, 1)
	go func() { sendExited <- owner.Send(&pb.IOStreamData{Data: []byte("business")}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	closeExited := make(chan ioStreamWriteShutdownResult, 1)

	// When
	go func() { closeExited <- owner.CloseSendAfterQuiescence(context.Background()) }()
	select {
	case operation := <-stream.writeEntered:
		t.Fatalf("%s entered before blocked business Send joined", operation)
	default:
	}
	stream.releaseWrite(streamWriteSend, nil)
	if err := awaitStreamOperationResult(t, sendExited); err != nil {
		t.Fatalf("business Send returned error: %v", err)
	}
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	result := awaitStreamOperationResult(t, closeExited)

	// Then
	if result.Err != nil || result.Forced {
		t.Fatalf("close result = %+v, want graceful success", result)
	}
	observation := stream.observe()
	assertStreamEvents(t, observation.events, []string{"send:start:1", "send:end:1", "close_send:start:1", "close_send:end:1"})
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("write observation = %+v, want serialized single close", observation)
	}
}

func TestIOStreamWriteOwner_CloseSendAfterQuiescenceJoinsBlockedKeepalive(t *testing.T) {
	// Given
	stream := newIOStreamFixture(context.Background(), streamCallAllowance{send: 1, closeSend: 1})
	owner := newIOStreamWriteOwner(stream, func(error) {})
	if err := owner.StartKeepalive(time.Nanosecond); err != nil {
		t.Fatalf("StartKeepalive returned error: %v", err)
	}
	stream.waitWriteEntered(t, streamWriteSend)
	closeExited := make(chan ioStreamWriteShutdownResult, 1)

	// When
	go func() { closeExited <- owner.CloseSendAfterQuiescence(context.Background()) }()
	awaitStreamSignal(t, owner.keepaliveStop, "keepalive stop before close")
	select {
	case operation := <-stream.writeEntered:
		t.Fatalf("%s entered before blocked keepalive joined", operation)
	default:
	}
	stream.releaseWrite(streamWriteSend, nil)
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	result := awaitStreamOperationResult(t, closeExited)

	// Then
	if result.Err != nil || result.Forced {
		t.Fatalf("close result = %+v, want graceful success", result)
	}
	observation := stream.observe()
	assertStreamEvents(t, observation.events, []string{"send:start:1", "send:end:1", "close_send:start:1", "close_send:end:1"})
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("write observation = %+v, want serialized single close", observation)
	}
}

func TestIOStreamWriteOwner_CloseSendAfterQuiescenceReturnsCloseErrorAndCancels(t *testing.T) {
	// Given
	streamContext, cancelStreamContext := context.WithCancelCause(context.Background())
	stream := newIOStreamFixture(streamContext, streamCallAllowance{closeSend: 1})
	owner := newIOStreamWriteOwner(stream, cancelStreamContext)
	closeErr := errors.New("close send failed")
	closeExited := make(chan ioStreamWriteShutdownResult, 1)

	// When
	go func() { closeExited <- owner.CloseSendAfterQuiescence(context.Background()) }()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, closeErr)
	result := awaitStreamOperationResult(t, closeExited)

	// Then
	if !errors.Is(result.Err, closeErr) || result.Forced {
		t.Fatalf("close result = %+v, want close error without forced pre-close", result)
	}
	if !errors.Is(context.Cause(streamContext), closeErr) {
		t.Fatalf("stream cancel cause = %v, want %v", context.Cause(streamContext), closeErr)
	}
	observation := stream.observe()
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("write observation = %+v, want serialized single close", observation)
	}
}
