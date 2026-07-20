package main

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestGRPCIdleRequestTask_TCPDeliversAfterIdleAndCancelsBoundedly(t *testing.T) {
	// Given
	started := make(chan struct{}, 1)
	releaseTask := make(chan struct{})
	resultReceived := make(chan *pb.TaskResult, 1)
	serverCanceled := make(chan error, 1)
	service := &grpcTCPService{
		requestTask: func(stream pb.NezhaService_RequestTaskServer) error {
			started <- struct{}{}
			<-releaseTask
			if err := stream.Send(&pb.Task{Id: 720, Type: model.TaskTypeKeepalive}); err != nil {
				return err
			}
			result, err := stream.Recv()
			if err != nil {
				return err
			}
			resultReceived <- result
			<-stream.Context().Done()
			serverCanceled <- stream.Context().Err()
			return stream.Context().Err()
		},
		reportSystemState: func(pb.NezhaService_ReportSystemStateServer) error { return nil },
		ioStream:          func(pb.NezhaService_IOStreamServer) error { return nil },
	}
	fixture := newGRPCTCPFixture(t, service)
	parent, cancelParent := context.WithCancel(context.Background())
	session := newConnectionSession(parent)
	stream, err := fixture.client.RequestTask(session.requestTaskContext)
	if err != nil {
		t.Fatalf("open RequestTask: %v", err)
	}
	requestSession := session.bindRequestTask(stream)
	session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })
	awaitStreamSignal(t, started, "tcp RequestTask start")
	if session.requestTaskContext.Err() != nil {
		t.Fatalf("RequestTask canceled while idle: %v", session.requestTaskContext.Err())
	}

	// When
	close(releaseTask)
	result := awaitStreamOperationResult(t, resultReceived)

	// Then
	if result.GetId() != 720 || result.GetType() != model.TaskTypeKeepalive {
		t.Fatalf("task result = id:%d type:%d, want id:720 type:%d", result.GetId(), result.GetType(), model.TaskTypeKeepalive)
	}
	if session.requestTaskContext.Err() != nil {
		t.Fatalf("RequestTask canceled after idle delivery: %v", session.requestTaskContext.Err())
	}
	cancelParent()
	if err := awaitStreamOperationResult(t, serverCanceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("server RequestTask context = %v, want context.Canceled", err)
	}
	grace, cancelGrace := context.WithTimeout(context.Background(), streamFixtureDeadline)
	defer cancelGrace()
	session.stopAndWait(grace, context.Canceled)
}

func TestGRPCCancellation_RequestTaskPeerFailureEndsDaemon(t *testing.T) {
	// Given
	serverErr := errors.New("request peer failure")
	service := &grpcTCPService{
		requestTask:       func(pb.NezhaService_RequestTaskServer) error { return serverErr },
		reportSystemState: func(pb.NezhaService_ReportSystemStateServer) error { return nil },
		ioStream:          func(pb.NezhaService_IOStreamServer) error { return nil },
	}
	fixture := newGRPCTCPFixture(t, service)
	session := newConnectionSession(context.Background())
	stream, err := fixture.client.RequestTask(session.requestTaskContext)
	if err != nil {
		t.Fatalf("open RequestTask: %v", err)
	}
	requestSession := session.bindRequestTask(stream)
	session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })

	// When
	awaitStreamSignal(t, session.exitContext.Done(), "RequestTask peer failure")
	grace, cancelGrace := context.WithTimeout(context.Background(), streamFixtureDeadline)
	defer cancelGrace()
	session.stopAndWait(grace, context.Cause(session.exitContext))

	// Then
	if session.longLivedStreamTasks.activeCount() != 0 {
		t.Fatalf("RequestTask failure active registry = %d, want 0", session.longLivedStreamTasks.activeCount())
	}
}

func TestGRPCGracefulClose_ReportStateUsesEOFAndTrailers(t *testing.T) {
	// Given
	stateReceived := make(chan *pb.State, 1)
	serverReturned := make(chan error, 1)
	service := &grpcTCPService{
		requestTask: func(pb.NezhaService_RequestTaskServer) error { return nil },
		reportSystemState: func(stream pb.NezhaService_ReportSystemStateServer) error {
			state, err := stream.Recv()
			if err != nil {
				return err
			}
			stateReceived <- state
			if err := stream.Send(&pb.Receipt{}); err != nil {
				return err
			}
			_, err = stream.Recv()
			if !errors.Is(err, io.EOF) {
				return status.Errorf(codes.Internal, "want client EOF, got %v", err)
			}
			stream.SetTrailer(metadata.Pairs("x-grpc-lifecycle", "report-ok"))
			return nil
		},
		ioStream: func(pb.NezhaService_IOStreamServer) error { return nil },
	}
	fixture := newGRPCTCPFixture(t, service)
	session := newConnectionSession(context.Background())
	reportSession, err := openReportState(session, fixture.client)
	if err != nil {
		t.Fatalf("open ReportSystemState: %v", err)
	}

	// When
	if err := reportSession.Send(&pb.State{}); err != nil {
		t.Fatalf("send state: %v", err)
	}
	awaitStreamOperationResult(t, stateReceived)
	if _, err := reportSession.Recv(); err != nil {
		t.Fatalf("receive receipt: %v", err)
	}
	go func() {
		_, recvErr := reportSession.Recv()
		serverReturned <- recvErr
	}()
	grace, cancelGrace := context.WithTimeout(context.Background(), streamFixtureDeadline)
	defer cancelGrace()
	shutdown := reportSession.shutdown(grace, context.Canceled)

	// Then
	if shutdown.Forced || shutdown.Err != nil {
		t.Fatalf("report shutdown = %+v, want graceful", shutdown)
	}
	if err := awaitStreamOperationResult(t, serverReturned); !errors.Is(err, io.EOF) {
		t.Fatalf("client terminal error = %v, want io.EOF", err)
	}
	if got := reportSession.stream.Trailer().Get("x-grpc-lifecycle"); len(got) != 1 || got[0] != "report-ok" {
		t.Fatalf("report trailer = %v, want report-ok", got)
	}
}

func TestGRPCCancellation_ReportStatePropagatesCanceledStatus(t *testing.T) {
	// Given
	started := make(chan struct{}, 1)
	serverCanceled := make(chan error, 1)
	service := &grpcTCPService{
		requestTask: func(pb.NezhaService_RequestTaskServer) error { return nil },
		reportSystemState: func(stream pb.NezhaService_ReportSystemStateServer) error {
			started <- struct{}{}
			<-stream.Context().Done()
			serverCanceled <- stream.Context().Err()
			return stream.Context().Err()
		},
		ioStream: func(pb.NezhaService_IOStreamServer) error { return nil },
	}
	fixture := newGRPCTCPFixture(t, service)
	parent, cancelParent := context.WithCancel(context.Background())
	stream, err := fixture.client.ReportSystemState(parent)
	if err != nil {
		t.Fatalf("open ReportSystemState: %v", err)
	}
	awaitStreamSignal(t, started, "tcp ReportSystemState start")

	// When
	cancelParent()
	_, recvErr := stream.Recv()

	// Then
	if status.Code(recvErr) != codes.Canceled {
		t.Fatalf("client status = %v, want Canceled: %v", status.Code(recvErr), recvErr)
	}
	if err := awaitStreamOperationResult(t, serverCanceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("server ReportSystemState context = %v, want context.Canceled", err)
	}
}
