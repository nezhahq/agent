package main

import (
	"context"
	"errors"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

func TestReceiveTasksDaemon_ExitsWhenConnectionContextCanceled(t *testing.T) {
	// Given
	fixture := newBufconnFixture(t)
	connectionContext, cancelConnection := context.WithCancel(context.Background())
	session := newConnectionSession(connectionContext)
	stream, err := fixture.client.RequestTask(session.requestTaskContext)
	if err != nil {
		t.Fatalf("RequestTask returned error: %v", err)
	}
	requestSession := session.bindRequestTask(stream)
	session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })
	fixture.waitRequestTaskStarted(t)

	// When
	cancelConnection()
	session.waitForDaemons()
	serverErr := fixture.waitRequestTaskCanceled(t)

	// Then
	if !errors.Is(serverErr, context.Canceled) {
		t.Fatalf("RequestTask server cancellation = %v, want context.Canceled", serverErr)
	}
	if !errors.Is(context.Cause(session.streamContext), context.Canceled) {
		t.Fatalf("stream context cause = %v, want context.Canceled", context.Cause(session.streamContext))
	}
}

type delayedRecvExitRequestTaskStream struct {
	pb.NezhaService_RequestTaskClient
	recvReleased chan struct{}
	allowExit    chan struct{}
}

func (s *delayedRecvExitRequestTaskStream) Recv() (*pb.Task, error) {
	task, err := s.NezhaService_RequestTaskClient.Recv()
	close(s.recvReleased)
	<-s.allowExit
	return task, err
}

func TestReceiveTasksDaemon_JoinsBeforeReconnect(t *testing.T) {
	// Given
	session := newConnectionSession(context.Background())
	baseStream := newRequestTaskStreamFixture(session.requestTaskContext, streamCallAllowance{recv: 1, closeSend: 1})
	stream := &delayedRecvExitRequestTaskStream{
		NezhaService_RequestTaskClient: baseStream,
		recvReleased:                   make(chan struct{}),
		allowExit:                      make(chan struct{}),
	}
	requestSession := session.bindRequestTask(stream)
	session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })
	baseStream.waitRecvEntered(t)
	reconnected := make(chan struct{})
	reconnectFinished := make(chan struct{})
	go func() {
		reconnectAfterSessionExit(session, sessionShutdown{
			graceContext: context.Background(),
			cause:        errors.New("test reconnect"),
		}, func() { close(reconnected) })
		close(reconnectFinished)
	}()
	baseStream.waitWriteEntered(t, streamWriteCloseSend)
	baseStream.releaseWrite(streamWriteCloseSend, nil)
	awaitStreamSignal(t, stream.recvReleased, "RequestTask Recv cancellation")

	// When
	select {
	case <-reconnected:
		t.Fatal("reconnect started before RequestTask daemon exit")
	default:
	}
	close(stream.allowExit)
	awaitStreamSignal(t, reconnectFinished, "reconnect after RequestTask daemon exit")

	// Then
	select {
	case <-reconnected:
		t.Log("event order: Recv canceled -> daemon exit -> reconnect")
	default:
		t.Fatal("reconnect did not run after RequestTask daemon exit")
	}
}

func TestSessionCancelsLongLivedTasksBeforeStreamCancellation(t *testing.T) {
	// Given
	stopCause := errors.New("graceful reconnect")
	session := newConnectionSession(context.Background())
	longLivedTaskCanceled := make(chan struct{})
	allowLongLivedTaskExit := make(chan struct{})
	session.startLongLivedStreamTask(func(taskContext context.Context) {
		<-taskContext.Done()
		close(longLivedTaskCanceled)
		<-allowLongLivedTaskExit
	})
	stopped := make(chan struct{})
	go func() {
		session.stopAndWait(context.Background(), stopCause)
		close(stopped)
	}()
	awaitStreamSignal(t, longLivedTaskCanceled, "long-lived task cancellation")

	// When
	select {
	case <-session.streamContext.Done():
		t.Fatalf("stream context canceled before long-lived tasks exited: %v", context.Cause(session.streamContext))
	default:
	}
	close(allowLongLivedTaskExit)
	awaitStreamSignal(t, stopped, "connection session stop")

	// Then
	if !errors.Is(context.Cause(session.longLivedTaskContext), stopCause) {
		t.Fatalf("long-lived task cause = %v, want %v", context.Cause(session.longLivedTaskContext), stopCause)
	}
	if !errors.Is(context.Cause(session.streamContext), stopCause) {
		t.Fatalf("stream cause = %v, want %v", context.Cause(session.streamContext), stopCause)
	}
}
