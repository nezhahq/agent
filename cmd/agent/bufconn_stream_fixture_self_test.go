package main

import (
	"context"
	"errors"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBufconnFixture_ReleasesBlockedReportSystemStateRecv(t *testing.T) {
	// Given
	fixture := newBufconnFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := fixture.client.ReportSystemState(ctx)
	if err != nil {
		t.Fatalf("ReportSystemState returned error: %v", err)
	}
	result := make(chan streamOperationResult[*pb.Receipt], 1)
	go func() {
		message, recvErr := stream.Recv()
		result <- streamOperationResult[*pb.Receipt]{value: message, err: recvErr}
	}()
	fixture.waitReportSystemStateStarted(t)

	// When
	fixture.releaseReportSystemState(&pb.Receipt{Proced: true})
	completed := awaitStreamOperationResult(t, result)

	// Then
	if completed.err != nil {
		t.Fatalf("ReportSystemState Recv returned error: %v", completed.err)
	}
	if !completed.value.GetProced() {
		t.Fatalf("ReportSystemState receipt = %+v, want proced=true", completed.value)
	}
}

func TestBufconnFixture_ObservesCanceledBlockedIOStreamRecv(t *testing.T) {
	// Given
	fixture := newBufconnFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := fixture.client.IOStream(ctx)
	if err != nil {
		t.Fatalf("IOStream returned error: %v", err)
	}
	result := make(chan streamOperationResult[*pb.IOStreamData], 1)
	go func() {
		message, recvErr := stream.Recv()
		result <- streamOperationResult[*pb.IOStreamData]{value: message, err: recvErr}
	}()
	fixture.waitIOStreamStarted(t)

	// When
	cancel()
	completed := awaitStreamOperationResult(t, result)
	serverErr := fixture.waitIOStreamCanceled(t)

	// Then
	if status.Code(completed.err) != codes.Canceled {
		t.Fatalf("IOStream Recv status = %v, want codes.Canceled; error=%v", status.Code(completed.err), completed.err)
	}
	if !errors.Is(serverErr, context.Canceled) {
		t.Fatalf("IOStream server cancellation = %v, want context.Canceled", serverErr)
	}
}
