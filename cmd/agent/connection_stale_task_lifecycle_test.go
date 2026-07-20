package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestOneShotTaskResultRejectedAfterReconnect(t *testing.T) {
	// Given
	session := newConnectionSession(context.Background())
	stream := newRequestTaskStreamFixture(session.streamContext, streamCallAllowance{closeSend: 1})
	requestSession := session.bindRequestTask(stream)
	taskStarted := make(chan struct{})
	allowTaskResult := make(chan struct{})
	taskExited := make(chan struct{})
	cancelCalled := make(chan struct{}, 1)
	execution := agentTaskExecution{
		parent:  session.streamContext,
		session: session,
		send:    requestSession.Send,
		cancel:  func() { cancelCalled <- struct{}{} },
		runTask: func(context.Context, *model.AgentConfig, *pb.Task) *pb.TaskResult {
			close(taskStarted)
			<-allowTaskResult
			return &pb.TaskResult{Id: 44, Type: model.TaskTypeKeepalive}
		},
		onTaskExit: func() { close(taskExited) },
	}
	execution.dispatch(&pb.Task{Id: 44, Type: model.TaskTypeKeepalive})
	awaitStreamSignal(t, taskStarted, "bounded one-shot start")
	reconnected := make(chan struct{})
	reconnectFinished := make(chan struct{})
	go func() {
		reconnectAfterSessionExit(session, sessionShutdown{
			graceContext: context.Background(),
			cause:        errors.New("reload"),
		}, func() { close(reconnected) })
		close(reconnectFinished)
	}()
	stream.waitWriteEntered(t, streamWriteCloseSend)

	// When
	stream.releaseWrite(streamWriteCloseSend, nil)
	awaitStreamSignal(t, reconnectFinished, "reconnect without bounded one-shot join")
	close(allowTaskResult)
	awaitStreamSignal(t, taskExited, "old one-shot exit")
	awaitStreamSignal(t, cancelCalled, "old one-shot result rejection")

	// Then
	select {
	case <-reconnected:
	default:
		t.Fatal("blocked bounded one-shot prevented reconnect")
	}
	observation := stream.observe()
	if observation.closeSendCount != 1 || len(observation.unexpectedCalls) != 0 {
		t.Fatalf("old session stream observation = %+v, want one close and no late Send", observation)
	}
}

func TestDispatchAgentTask_CapturesOneRuntimeSnapshot(t *testing.T) {
	// Given
	originalConfig := agentConfig
	originalSnapshot := loadRuntimeConfig().Clone()
	defer func() {
		agentConfig = originalConfig
		publishRuntimeConfig(originalSnapshot)
	}()
	firstSnapshot := setTestRuntimeConfig(model.AgentConfig{Server: "first.example:5555"})
	receivedSnapshot := make(chan *model.AgentConfig, 1)
	allowTaskExit := make(chan struct{})
	execution := agentTaskExecution{
		parent: context.Background(),
		send:   func(*pb.TaskResult) error { return nil },
		cancel: func() {},
		runTask: func(_ context.Context, snapshot *model.AgentConfig, _ *pb.Task) *pb.TaskResult {
			receivedSnapshot <- snapshot
			<-allowTaskExit
			return nil
		},
	}

	// When
	execution.dispatch(&pb.Task{Id: 45, Type: model.TaskTypeKeepalive})
	publishRuntimeConfig(model.AgentConfig{Server: "second.example:5555"})
	captured := awaitStreamOperationResult(t, receivedSnapshot)
	close(allowTaskExit)

	// Then
	if captured != firstSnapshot {
		t.Fatalf("task snapshot pointer = %p, want dispatch snapshot %p", captured, firstSnapshot)
	}
	if captured.Server != "first.example:5555" {
		t.Fatalf("task snapshot server = %q, want first.example:5555", captured.Server)
	}
}

func TestRequestTaskResultSendError_ReconnectsAfterDaemonExit(t *testing.T) {
	// Given
	errSend := errors.New("result send failed")
	session := newConnectionSession(context.Background())
	stream := newRequestTaskStreamFixture(session.requestTaskContext, streamCallAllowance{
		send:      1,
		recv:      2,
		closeSend: 1,
	})
	requestSession := session.bindRequestTask(stream)
	session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })
	stream.waitRecvEntered(t)
	stream.releaseRecv(&pb.Task{Id: 47, Type: model.TaskTypeKeepalive}, nil)
	stream.waitWriteEntered(t, streamWriteSend)
	stream.releaseWrite(streamWriteSend, errSend)
	awaitStreamSignal(t, session.exitContext.Done(), "RequestTask result Send error exit signal")
	reconnected := make(chan struct{})
	reconnectFinished := make(chan struct{})

	// When
	go func() {
		reconnectAfterSessionExit(session, sessionShutdown{
			graceContext: context.Background(),
			cause:        context.Cause(session.exitContext),
		}, func() { close(reconnected) })
		close(reconnectFinished)
	}()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	awaitStreamSignal(t, reconnectFinished, "reconnect after result Send error")

	// Then
	if !errors.Is(context.Cause(session.requestTaskContext), errSend) {
		t.Fatalf("RequestTask context cause = %v, want %v", context.Cause(session.requestTaskContext), errSend)
	}
	select {
	case <-reconnected:
	default:
		t.Fatal("result Send error did not complete reconnect after daemon exit")
	}
	observation := stream.observe()
	if observation.closeSendCount != 1 || len(observation.unexpectedCalls) != 0 {
		t.Fatalf("RequestTask observation = %+v, want one close and no unexpected calls", observation)
	}
}
