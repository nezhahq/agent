package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestReportStateStreamContext_CancelsWithConnectionParent(t *testing.T) {
	// Given
	parent, cancelParent := context.WithCancel(context.Background())
	session := newConnectionSession(parent)
	reportSession := session.newReportStateSession()
	stream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{recv: 1})
	reportSession.bind(stream)
	recvExited := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		recvExited <- err
	}()
	stream.waitRecvEntered(t)

	// When
	cancelParent()
	recvErr := awaitStreamOperationResult(t, recvExited)

	// Then
	if !errors.Is(recvErr, context.Canceled) {
		t.Fatalf("ReportSystemState Recv error = %v, want context.Canceled", recvErr)
	}
	if !errors.Is(context.Cause(reportSession.streamContext), context.Canceled) {
		t.Fatalf("ReportSystemState context cause = %v, want context.Canceled", context.Cause(reportSession.streamContext))
	}
}

func TestReportStateContext_ShutdownStopsCadenceBeforeNextSend(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given
		originalSnapshot := runtimeConfigSnapshot.Load()
		originalDependencies := reportMonitorDependencies
		originalInitialized := initialized
		originalGeoIPReported := geoipReported
		originalHostReport := lastReportHostInfo
		originalIPReport := lastReportIPInfo
		t.Cleanup(func() {
			runtimeConfigSnapshot.Store(originalSnapshot)
			reportMonitorDependencies = originalDependencies
			initialized = originalInitialized
			geoipReported = originalGeoIPReported
			lastReportHostInfo = originalHostReport
			lastReportIPInfo = originalIPReport
		})
		publishRuntimeConfig(model.AgentConfig{ReportDelay: 60, IPReportPeriod: 600})
		reportMonitorDependencies.trackNetworkSpeed = func(*model.AgentConfig) {}
		reportMonitorDependencies.getState = func(*model.AgentConfig, bool, bool) *model.HostState {
			return &model.HostState{}
		}
		initialized = true
		geoipReported = true
		lastReportHostInfo = time.Now().Add(time.Hour)
		lastReportIPInfo = time.Now().Add(time.Hour)

		session := newConnectionSession(context.Background())
		reportSession := session.newReportStateSession()
		stream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{send: 1, recv: 2, closeSend: 1})
		session.bindReportState(reportSession, stream)
		session.startDaemon(func() { reportStateDaemon(reportSession, session.signalExit) })
		<-stream.writeEntered
		stream.releaseWrite(streamWriteSend, nil)
		<-stream.recvEntered
		stream.releaseRecv(nil, nil)
		synctest.Wait()
		shutdownExited := make(chan struct{})
		go func() {
			session.stopAndWait(context.Background(), context.Canceled)
			close(shutdownExited)
		}()
		<-stream.writeEntered

		// When
		stream.releaseWrite(streamWriteCloseSend, nil)
		<-stream.recvEntered
		stream.releaseRecv(nil, io.EOF)
		synctest.Wait()
		<-shutdownExited
		time.Sleep(time.Hour)
		synctest.Wait()

		// Then
		observation := stream.observe()
		assertReportStateTerminalInterleaving(t, observation, len(stream.sentMessages()))
		if observation.closeSendCount != 1 {
			t.Fatalf("ReportState CloseSend count = %d, want 1", observation.closeSendCount)
		}
	})
}

func assertReportStateTerminalInterleaving(t *testing.T, observation streamObservation, sentCount int) {
	t.Helper()
	wantPrefix := []string{"send:start:1", "send:end:1", "recv:start:1", "recv:end:1"}
	if len(observation.events) != 8 || fmt.Sprint(observation.events[:4]) != fmt.Sprint(wantPrefix) {
		t.Fatalf("ReportState events = %v, want initial prefix %v and 8 total events", observation.events, wantPrefix)
	}
	wantTerminal := map[string]int{
		"close_send:start:1": 1,
		"close_send:end:1":   1,
		"recv:start:2":       1,
		"recv:end:2":         1,
	}
	indexes := make(map[string]int, len(wantTerminal))
	for index, event := range observation.events[4:] {
		if wantTerminal[event] == 0 {
			t.Fatalf("ReportState terminal events = %v, unexpected %q", observation.events[4:], event)
		}
		wantTerminal[event]--
		indexes[event] = index
	}
	for event, remaining := range wantTerminal {
		if remaining != 0 {
			t.Fatalf("ReportState terminal events = %v, count for %q is not exactly one", observation.events[4:], event)
		}
	}
	if indexes["close_send:start:1"] >= indexes["close_send:end:1"] {
		t.Fatalf("ReportState CloseSend order = %v, want start before end", observation.events[4:])
	}
	if indexes["recv:start:2"] >= indexes["recv:end:2"] {
		t.Fatalf("ReportState terminal Recv order = %v, want start before end", observation.events[4:])
	}
	if sentCount != 1 || len(observation.unexpectedCalls) != 0 {
		t.Fatalf("ReportState calls: sends=%d unexpected=%v, want one send and no unexpected calls", sentCount, observation.unexpectedCalls)
	}
}

func TestReportStateSession_SerializesBlockedSendAndClosesOnce(t *testing.T) {
	// Given
	session := newConnectionSession(context.Background())
	reportSession := session.newReportStateSession()
	stream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{send: 1, closeSend: 1})
	reportSession.bind(stream)
	sendExited := make(chan error, 1)
	go func() { sendExited <- reportSession.Send(&pb.State{}) }()
	stream.waitWriteEntered(t, streamWriteSend)
	shutdownExited := make(chan reportStateShutdownResult, 1)
	go func() { shutdownExited <- reportSession.shutdown(context.Background(), context.Canceled) }()

	// When
	select {
	case operation := <-stream.writeEntered:
		t.Fatalf("CloseSend overlapped blocked Send: %s", operation)
	default:
	}
	stream.releaseWrite(streamWriteSend, nil)
	if err := awaitStreamOperationResult(t, sendExited); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	if result := awaitStreamOperationResult(t, shutdownExited); result.Err != nil || result.Forced {
		t.Fatalf("shutdown result = %+v, want graceful success", result)
	}
	if result := reportSession.shutdown(context.Background(), context.Canceled); result.Err != nil || result.Forced {
		t.Fatalf("second shutdown result = %+v, want graceful success", result)
	}

	// Then
	observation := stream.observe()
	if observation.maxWriteInFlight != 1 {
		t.Fatalf("ReportState Send/CloseSend max concurrency = %d, want 1", observation.maxWriteInFlight)
	}
	if observation.closeSendCount != 1 {
		t.Fatalf("ReportState CloseSend count = %d, want 1", observation.closeSendCount)
	}
	assertStreamEvents(t, observation.events, []string{
		"send:start:1", "send:end:1", "close_send:start:1", "close_send:end:1",
	})
}

func TestReportStateSession_RejectsSendAfterClosingAndRetainsFirstError(t *testing.T) {
	// Given
	session := newConnectionSession(context.Background())
	reportSession := session.newReportStateSession()
	stream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{closeSend: 1})
	reportSession.bind(stream)
	closeErr := errors.New("close failed")
	shutdownExited := make(chan reportStateShutdownResult, 1)
	go func() { shutdownExited <- reportSession.shutdown(context.Background(), context.Canceled) }()
	stream.waitWriteEntered(t, streamWriteCloseSend)

	// When
	stream.releaseWrite(streamWriteCloseSend, closeErr)
	firstResult := awaitStreamOperationResult(t, shutdownExited)
	sendErr := reportSession.Send(&pb.State{})
	secondResult := reportSession.shutdown(context.Background(), context.Canceled)

	// Then
	if !errors.Is(firstResult.Err, closeErr) || !errors.Is(secondResult.Err, closeErr) {
		t.Fatalf("terminal results = (%+v, %+v), want retained %v", firstResult, secondResult, closeErr)
	}
	if !errors.Is(sendErr, errReportStateWriteClosed) {
		t.Fatalf("send after close error = %v, want %v", sendErr, errReportStateWriteClosed)
	}
	observation := stream.observe()
	if observation.closeSendCount != 1 {
		t.Fatalf("ReportState CloseSend count = %d, want 1", observation.closeSendCount)
	}
}
