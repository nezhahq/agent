package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestDispatchAgentTask_LongLivedHandlersJoinBeforeReconnect(t *testing.T) {
	longLivedTypes := []struct {
		name     string
		taskType uint64
	}{
		{name: "terminal", taskType: model.TaskTypeTerminalGRPC},
		{name: "nat", taskType: model.TaskTypeNAT},
		{name: "fm", taskType: model.TaskTypeFM},
		{name: "fs_transfer", taskType: model.TaskTypeFsTransfer},
	}

	for _, testCase := range longLivedTypes {
		t.Run(testCase.name, func(t *testing.T) {
			// Given
			session := newConnectionSession(context.Background())
			started := make(chan context.Context, 1)
			allowExit := make(chan struct{})
			execution := agentTaskExecution{
				parent:  session.streamContext,
				session: session,
				send:    func(*pb.TaskResult) error { return nil },
				cancel:  func() {},
				runTask: func(taskContext context.Context, _ *model.AgentConfig, _ *pb.Task) *pb.TaskResult {
					started <- taskContext
					<-taskContext.Done()
					<-allowExit
					return nil
				},
			}
			execution.dispatch(&pb.Task{Id: 1, Type: testCase.taskType})
			taskContext := awaitStreamOperationResult(t, started)
			reconnected := make(chan struct{})
			reconnectFinished := make(chan struct{})
			go func() {
				reconnectAfterSessionExit(session, sessionShutdown{
					graceContext: context.Background(),
					cause:        errors.New("reload"),
				}, func() { close(reconnected) })
				close(reconnectFinished)
			}()
			awaitStreamSignal(t, taskContext.Done(), "long-lived task cancellation")

			// When
			select {
			case <-reconnected:
				t.Fatal("reconnect started before long-lived handler exited")
			default:
			}
			close(allowExit)
			awaitStreamSignal(t, reconnectFinished, "reconnect after long-lived handler exit")

			// Then
			select {
			case <-reconnected:
			default:
				t.Fatal("reconnect did not run after long-lived handler exit")
			}
		})
	}
}

func TestDispatchAgentTask_RejectsLongLivedHandlerAfterRegistryClose(t *testing.T) {
	// Given
	session := newConnectionSession(context.Background())
	session.longLivedStreamTasks.closeRegistration()
	handlerStarted := make(chan struct{}, 1)
	execution := agentTaskExecution{
		parent:  session.streamContext,
		session: session,
		send:    func(*pb.TaskResult) error { return nil },
		cancel:  func() {},
		runTask: func(context.Context, *model.AgentConfig, *pb.Task) *pb.TaskResult {
			handlerStarted <- struct{}{}
			return nil
		},
	}

	// When
	execution.dispatch(&pb.Task{Id: 46, Type: model.TaskTypeTerminalGRPC})
	session.longLivedStreamTasks.wait()

	// Then
	select {
	case <-handlerStarted:
		t.Fatal("long-lived handler started after registry closed")
	default:
	}
	if count := session.longLivedStreamTasks.activeCount(); count != 0 {
		t.Fatalf("active registry count = %d, want 0", count)
	}
}

func TestStreamTaskRegistry_RejectsRegistrationAfterClose(t *testing.T) {
	// Given
	registry := newStreamTaskRegistry()
	activeStarted := make(chan struct{})
	allowActiveExit := make(chan struct{})
	if !registry.start(func() {
		close(activeStarted)
		<-allowActiveExit
	}) {
		t.Fatal("initial registration was rejected")
	}
	awaitStreamSignal(t, activeStarted, "initial registered task start")

	// When
	registry.closeRegistration()
	lateStarted := make(chan struct{})
	accepted := registry.start(func() { close(lateStarted) })
	close(allowActiveExit)
	registry.wait()

	// Then
	if accepted {
		t.Fatal("registration succeeded after registry closure")
	}
	select {
	case <-lateStarted:
		t.Fatal("rejected registration still launched")
	default:
	}
	if count := registry.activeCount(); count != 0 {
		t.Fatalf("active registry count = %d, want 0", count)
	}
}

func TestStreamTaskRegistry_ClosePreventsConcurrentAddAfterWait(t *testing.T) {
	// Given
	registry := newStreamTaskRegistry()
	startGate := make(chan struct{})
	registrationResults := make(chan bool, 64)
	for range 64 {
		go func() {
			<-startGate
			registrationResults <- registry.start(func() {})
		}()
	}

	// When
	close(startGate)
	registry.closeRegistration()
	for range 64 {
		<-registrationResults
	}
	registry.wait()

	// Then
	if registry.start(func() {}) {
		t.Fatal("registry accepted Add after close and Wait")
	}
	if count := registry.activeCount(); count != 0 {
		t.Fatalf("active registry count after Wait = %d, want 0", count)
	}
}

func TestWorkerDaemonsJoinBeforeReconnect(t *testing.T) {
	// Given
	session := newConnectionSession(context.Background())
	daemonCanceled := make(chan struct{})
	allowDaemonExit := make(chan struct{})
	session.startDaemon(func() {
		<-session.streamContext.Done()
		close(daemonCanceled)
		<-allowDaemonExit
	})
	reconnected := make(chan struct{})
	reconnectFinished := make(chan struct{})
	go func() {
		reconnectAfterSessionExit(session, sessionShutdown{
			graceContext: context.Background(),
			cause:        errors.New("reload"),
		}, func() { close(reconnected) })
		close(reconnectFinished)
	}()
	awaitStreamSignal(t, daemonCanceled, "daemon stream cancellation")

	// When
	select {
	case <-reconnected:
		t.Fatal("reconnect started before daemon exited")
	default:
	}
	close(allowDaemonExit)
	awaitStreamSignal(t, reconnectFinished, "reconnect after daemon exit")

	// Then
	select {
	case <-reconnected:
	default:
		t.Fatal("reconnect did not run after daemon exit")
	}
}
