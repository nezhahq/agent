package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
)

type shutdownEventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *shutdownEventLog) record(event string) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *shutdownEventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

func TestConnectionSession_ShutdownOrderPrecedesReconnect(t *testing.T) {
	// Given
	stopCause := errors.New("reload")
	events := &shutdownEventLog{}
	session := newConnectionSession(context.Background())
	requestStream := newRequestTaskStreamFixture(session.requestTaskContext, streamCallAllowance{closeSend: 1})
	session.bindRequestTask(requestStream)
	reportSession := session.newReportStateSession()
	reportStream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{closeSend: 1})
	session.bindReportState(reportSession, reportStream)
	longTaskCanceled := make(chan struct{})
	allowLongTaskExit := make(chan struct{})
	session.startLongLivedStreamTask(func(taskContext context.Context) {
		<-taskContext.Done()
		events.record("long_task:canceled")
		close(longTaskCanceled)
		<-allowLongTaskExit
		events.record("long_task:exited")
	})
	daemonCanceled := make(chan struct{}, 2)
	allowDaemonsExit := make(chan struct{})
	for _, name := range []string{"request_daemon", "report_daemon"} {
		session.startDaemon(func() {
			<-session.streamContext.Done()
			daemonCanceled <- struct{}{}
			<-allowDaemonsExit
			events.record(name + ":exited")
		})
	}
	reconnectFinished := make(chan struct{})
	reconnectActiveCount := make(chan int, 1)
	go func() {
		reconnectAfterSessionExit(session, sessionShutdown{
			graceContext: context.Background(),
			cause:        stopCause,
		}, func() {
			events.record("reconnect")
			reconnectActiveCount <- session.longLivedStreamTasks.activeCount()
		})
		close(reconnectFinished)
	}()
	awaitStreamSignal(t, longTaskCanceled, "long-lived task cancellation")

	// When
	close(allowLongTaskExit)
	reportStream.waitWriteEntered(t, streamWriteCloseSend)
	events.record("report:close")
	reportStream.releaseWrite(streamWriteCloseSend, nil)
	reportSession.finishTerminal(io.EOF)
	requestStream.waitWriteEntered(t, streamWriteCloseSend)
	events.record("request:close")
	requestStream.releaseWrite(streamWriteCloseSend, nil)
	awaitStreamOperationResult(t, daemonCanceled)
	awaitStreamOperationResult(t, daemonCanceled)
	close(allowDaemonsExit)
	awaitStreamSignal(t, reconnectFinished, "reconnect after session shutdown")

	// Then
	got := events.snapshot()
	activeCount := awaitStreamOperationResult(t, reconnectActiveCount)
	t.Logf("shutdown event order: %v; registry active at reconnect: %d", got, activeCount)
	if activeCount != 0 {
		t.Fatalf("registry active count at reconnect = %d, want 0", activeCount)
	}
	if len(got) != 7 {
		t.Fatalf("shutdown events = %v, want 7 events", got)
	}
	if got[0] != "long_task:canceled" || got[1] != "long_task:exited" || got[2] != "report:close" || got[3] != "request:close" {
		t.Fatalf("shutdown prefix = %v, want long task cancel/exit then report/request close", got[:4])
	}
	if got[6] != "reconnect" {
		t.Fatalf("final shutdown event = %q, want reconnect", got[6])
	}
	daemonEvents := map[string]bool{}
	for _, event := range got[4:6] {
		daemonEvents[event] = true
	}
	for _, want := range []string{"request_daemon:exited", "report_daemon:exited"} {
		if !daemonEvents[want] {
			t.Fatalf("shutdown events = %v, missing %q before reconnect", got, want)
		}
	}
}
