package main

import (
	"context"
	"errors"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type streamOperationResult[T any] struct {
	value T
	err   error
}

func TestStreamFixture_ReleasesBlockedRecvWithConfiguredMessage(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newRequestTaskStreamFixture(ctx, streamCallAllowance{recv: 1})
	result := make(chan streamOperationResult[*pb.Task], 1)
	go func() {
		message, err := stream.Recv()
		result <- streamOperationResult[*pb.Task]{value: message, err: err}
	}()
	stream.waitRecvEntered(t)

	select {
	case completed := <-result:
		t.Fatalf("Recv completed before release: message=%v error=%v", completed.value, completed.err)
	default:
	}

	// When
	stream.releaseRecv(&pb.Task{Id: 41, Data: "released"}, nil)
	completed := awaitStreamOperationResult(t, result)

	// Then
	if completed.err != nil {
		t.Fatalf("Recv returned unexpected error: %v", completed.err)
	}
	if completed.value.GetId() != 41 || completed.value.GetData() != "released" {
		t.Fatalf("Recv returned unexpected task: %+v", completed.value)
	}
	observation := stream.observe()
	assertStreamEvents(t, observation.events, []string{"recv:start:1", "recv:end:1"})
}

func TestStreamFixture_ReportsContextCancellationFromBlockedRecv(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	stream := newReportSystemStateStreamFixture(ctx, streamCallAllowance{recv: 1})
	result := make(chan streamOperationResult[*pb.Receipt], 1)
	go func() {
		message, err := stream.Recv()
		result <- streamOperationResult[*pb.Receipt]{value: message, err: err}
	}()
	stream.waitRecvEntered(t)

	// When
	cancel()
	completed := awaitStreamOperationResult(t, result)

	// Then
	if !errors.Is(completed.err, context.Canceled) {
		t.Fatalf("Recv error = %v, want context.Canceled", completed.err)
	}
	observation := stream.observe()
	if !observation.contextCancellationObserved {
		t.Fatal("fixture did not record context cancellation")
	}
	assertStreamEvents(t, observation.events, []string{"recv:start:1", "recv:canceled:1"})
}

func TestStreamFixture_RecordsSerializedSendMaxInFlightOne(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newRequestTaskStreamFixture(ctx, streamCallAllowance{send: 2})
	session := newRequestTaskSession(stream, func(error) { cancel() })
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- session.Send(&pb.TaskResult{Id: 1}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	secondAttempted := make(chan struct{})
	go func() {
		close(secondAttempted)
		second <- session.Send(&pb.TaskResult{Id: 2})
	}()
	<-secondAttempted

	// When
	stream.releaseWrite(streamWriteSend, nil)
	stream.waitWriteEntered(t, streamWriteSend)
	stream.releaseWrite(streamWriteSend, nil)

	// Then
	if err := awaitStreamOperationResult(t, first); err != nil {
		t.Fatalf("first serialized Send returned error: %v", err)
	}
	if err := awaitStreamOperationResult(t, second); err != nil {
		t.Fatalf("second serialized Send returned error: %v", err)
	}
	observation := stream.observe()
	t.Logf("serialized max-in-flight=%d", observation.maxWriteInFlight)
	if observation.maxWriteInFlight != 1 {
		t.Fatalf("serialized max-in-flight = %d, want 1", observation.maxWriteInFlight)
	}
	assertStreamEvents(t, observation.events, []string{
		"send:start:1", "send:end:1", "send:start:2", "send:end:2",
	})
	sent := stream.sentMessages()
	if len(sent) != 2 || sent[0].GetId() != 1 || sent[1].GetId() != 2 {
		t.Fatalf("serialized Send order = %+v, want task IDs [1 2]", sent)
	}
}

func TestStreamFixture_DetectsDeliberateRawSendOverlap(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newIOStreamFixture(ctx, streamCallAllowance{send: 2})
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- stream.Send(&pb.IOStreamData{Data: []byte("first")}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	go func() { second <- stream.Send(&pb.IOStreamData{Data: []byte("second")}) }()
	stream.waitWriteEntered(t, streamWriteSend)

	// When
	observation := stream.observe()
	t.Logf("deliberate raw overlap max-in-flight=%d", observation.maxWriteInFlight)
	stream.releaseWrite(streamWriteSend, nil)
	stream.releaseWrite(streamWriteSend, nil)

	// Then
	if observation.maxWriteInFlight <= 1 {
		t.Fatalf("raw overlap max-in-flight = %d, want >1", observation.maxWriteInFlight)
	}
	if err := awaitStreamOperationResult(t, first); err != nil {
		t.Fatalf("first raw Send returned error: %v", err)
	}
	if err := awaitStreamOperationResult(t, second); err != nil {
		t.Fatalf("second raw Send returned error: %v", err)
	}
}

func TestStreamFixture_DetectsDeliberateSendCloseOverlap(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newIOStreamFixture(ctx, streamCallAllowance{send: 1, closeSend: 1})
	sendResult := make(chan error, 1)
	closeResult := make(chan error, 1)
	go func() { sendResult <- stream.Send(&pb.IOStreamData{Data: []byte("frame")}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	go func() { closeResult <- stream.CloseSend() }()
	stream.waitWriteEntered(t, streamWriteCloseSend)

	// When
	observation := stream.observe()
	stream.releaseWrite(streamWriteSend, nil)
	if err := awaitStreamOperationResult(t, sendResult); err != nil {
		t.Fatalf("overlapping Send returned error: %v", err)
	}
	stream.releaseWrite(streamWriteCloseSend, nil)

	// Then
	if observation.maxWriteInFlight != 2 {
		t.Fatalf("Send/CloseSend max-in-flight = %d, want 2", observation.maxWriteInFlight)
	}
	if err := awaitStreamOperationResult(t, closeResult); err != nil {
		t.Fatalf("overlapping CloseSend returned error: %v", err)
	}
	assertStreamEvents(t, stream.observe().events, []string{
		"send:start:1", "close_send:start:1", "send:end:1", "close_send:end:1",
	})
}

func TestStreamFixture_DetectsDuplicateCloseAndUnexpectedLowLevelCall(t *testing.T) {
	// Given
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newIOStreamFixture(ctx, streamCallAllowance{closeSend: 1})
	firstClose := make(chan error, 1)
	go func() { firstClose <- stream.CloseSend() }()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	if err := awaitStreamOperationResult(t, firstClose); err != nil {
		t.Fatalf("first CloseSend returned error: %v", err)
	}

	// When
	duplicateErr := stream.CloseSend()
	lowLevelErr := stream.SendMsg("malformed low-level input")

	// Then
	if !errors.Is(duplicateErr, errUnexpectedStreamCall) {
		t.Fatalf("duplicate CloseSend error = %v, want errUnexpectedStreamCall", duplicateErr)
	}
	if !errors.Is(lowLevelErr, errUnexpectedStreamCall) {
		t.Fatalf("unexpected SendMsg error = %v, want errUnexpectedStreamCall", lowLevelErr)
	}
	observation := stream.observe()
	t.Logf("duplicate close count=%d unexpected-calls=%v", observation.closeSendCount, observation.unexpectedCalls)
	if observation.closeSendCount != 2 {
		t.Fatalf("CloseSend count = %d, want 2", observation.closeSendCount)
	}
	assertStreamEvents(t, observation.unexpectedCalls, []string{"close_send:2", "send_msg:1"})
}

func TestBufconnFixture_ReleasesBlockedRequestTaskRecv(t *testing.T) {
	// Given
	fixture := newBufconnFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := fixture.client.RequestTask(ctx)
	if err != nil {
		t.Fatalf("RequestTask returned error: %v", err)
	}
	result := make(chan streamOperationResult[*pb.Task], 1)
	go func() {
		message, recvErr := stream.Recv()
		result <- streamOperationResult[*pb.Task]{value: message, err: recvErr}
	}()
	fixture.waitRequestTaskStarted(t)

	// When
	fixture.releaseRequestTask(&pb.Task{Id: 77, Data: "bufconn"})
	completed := awaitStreamOperationResult(t, result)

	// Then
	if completed.err != nil {
		t.Fatalf("bufconn Recv returned error: %v", completed.err)
	}
	if completed.value.GetId() != 77 || completed.value.GetData() != "bufconn" {
		t.Fatalf("bufconn Recv returned unexpected task: %+v", completed.value)
	}
}

func TestBufconnFixture_ObservesCanceledBlockedRequestTaskRecv(t *testing.T) {
	// Given
	fixture := newBufconnFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := fixture.client.RequestTask(ctx)
	if err != nil {
		t.Fatalf("RequestTask returned error: %v", err)
	}
	result := make(chan streamOperationResult[*pb.Task], 1)
	go func() {
		message, recvErr := stream.Recv()
		result <- streamOperationResult[*pb.Task]{value: message, err: recvErr}
	}()
	fixture.waitRequestTaskStarted(t)

	// When
	cancel()
	completed := awaitStreamOperationResult(t, result)
	serverErr := fixture.waitRequestTaskCanceled(t)

	// Then
	if status.Code(completed.err) != codes.Canceled {
		t.Fatalf("bufconn Recv status = %v, want codes.Canceled; error=%v", status.Code(completed.err), completed.err)
	}
	if !errors.Is(serverErr, context.Canceled) {
		t.Fatalf("server cancellation = %v, want context.Canceled", serverErr)
	}
}
