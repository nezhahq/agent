package main

import (
	"context"
	"errors"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
)

type reportStateConstructionFailureClient struct {
	pb.NezhaServiceClient
	err           error
	streamContext chan context.Context
}

func (c *reportStateConstructionFailureClient) ReportSystemState(
	ctx context.Context,
	_ ...grpc.CallOption,
) (pb.NezhaService_ReportSystemStateClient, error) {
	c.streamContext <- ctx
	return nil, c.err
}

type reportStateConstructionOutcome struct {
	panicValue any
	returned   bool
}

func TestReportStateConstructionFailure_ReconnectsWithoutUnboundShutdownPanic(t *testing.T) {
	// Given
	constructionErr := errors.New("ReportSystemState construction failed")
	session := newConnectionSession(context.Background())
	tasks := newRequestTaskStreamFixture(session.requestTaskContext, streamCallAllowance{recv: 1, closeSend: 1})
	requestSession := session.bindRequestTask(tasks)
	session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })
	tasks.waitRecvEntered(t)
	failingClient := &reportStateConstructionFailureClient{
		err:           constructionErr,
		streamContext: make(chan context.Context, 1),
	}
	retried := make(chan struct{})
	outcome := make(chan reportStateConstructionOutcome, 1)

	// When
	go func() {
		result := reportStateConstructionOutcome{}
		defer func() {
			result.panicValue = recover()
			outcome <- result
		}()
		_, err := openReportState(session, failingClient)
		if !errors.Is(err, constructionErr) {
			panic("unexpected construction error")
		}
		reconnectAfterSessionExit(session, sessionShutdown{
			graceContext: context.Background(),
			cause:        err,
		}, func() { close(retried) })
		result.returned = true
	}()
	tasks.waitWriteEntered(t, streamWriteCloseSend)
	tasks.releaseWrite(streamWriteCloseSend, nil)
	result := awaitStreamOperationResult(t, outcome)
	failedStreamContext := awaitStreamOperationResult(t, failingClient.streamContext)

	// Then
	if result.panicValue != nil {
		t.Fatalf("ReportState construction failure cleanup panicked: %v", result.panicValue)
	}
	if !result.returned {
		t.Fatal("ReportState construction failure cleanup did not return")
	}
	awaitStreamSignal(t, retried, "ReportState construction failure retry")
	if session.reportState != nil {
		t.Fatal("failed ReportState candidate was published to connectionSession")
	}
	if !errors.Is(context.Cause(failedStreamContext), constructionErr) {
		t.Fatalf("failed ReportState context cause = %v, want %v", context.Cause(failedStreamContext), constructionErr)
	}
	if tasks.observe().closeSendCount != 1 {
		t.Fatalf("RequestTask CloseSend count = %d, want 1", tasks.observe().closeSendCount)
	}
}
