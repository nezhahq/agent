package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

type delayedRecvExitReportStateStream struct {
	pb.NezhaService_ReportSystemStateClient
	recvReleased chan struct{}
	allowExit    chan struct{}
}

func (s *delayedRecvExitReportStateStream) Recv() (*pb.Receipt, error) {
	receipt, err := s.NezhaService_ReportSystemStateClient.Recv()
	close(s.recvReleased)
	<-s.allowExit
	return receipt, err
}

func TestReportStateSession_SendErrorSignalsExitAndClosesOnce(t *testing.T) {
	// Given
	originalSnapshot := runtimeConfigSnapshot.Load()
	originalDependencies := reportMonitorDependencies
	originalInitialized := initialized
	t.Cleanup(func() {
		runtimeConfigSnapshot.Store(originalSnapshot)
		reportMonitorDependencies = originalDependencies
		initialized = originalInitialized
	})
	publishRuntimeConfig(model.AgentConfig{ReportDelay: 60})
	reportMonitorDependencies.trackNetworkSpeed = func(*model.AgentConfig) {}
	reportMonitorDependencies.getState = func(*model.AgentConfig, bool, bool) *model.HostState {
		return &model.HostState{}
	}
	initialized = true

	session := newConnectionSession(context.Background())
	reportSession := session.newReportStateSession()
	stream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{send: 1, closeSend: 1})
	session.bindReportState(reportSession, stream)
	sendErr := errors.New("state send failed")
	session.startDaemon(func() { reportStateDaemon(reportSession, session.signalExit) })
	stream.waitWriteEntered(t, streamWriteSend)

	// When
	stream.releaseWrite(streamWriteSend, sendErr)
	<-session.exitContext.Done()
	shutdownExited := make(chan reportStateShutdownResult, 1)
	go func() {
		shutdownExited <- reportSession.shutdown(context.Background(), context.Cause(session.exitContext))
	}()
	stream.waitWriteEntered(t, streamWriteCloseSend)
	stream.releaseWrite(streamWriteCloseSend, nil)
	shutdownResult := awaitStreamOperationResult(t, shutdownExited)
	rejectedSendErr := reportSession.Send(&pb.State{})
	repeatedResult := reportSession.shutdown(context.Background(), context.Canceled)
	session.cancelStream(sendErr)
	session.waitForDaemons()

	// Then
	if !errors.Is(shutdownResult.Err, sendErr) || shutdownResult.Forced {
		t.Fatalf("ReportState shutdown result = %+v, want graceful retained %v", shutdownResult, sendErr)
	}
	if !errors.Is(rejectedSendErr, errReportStateWriteClosed) {
		t.Fatalf("Send after terminal error = %v, want %v", rejectedSendErr, errReportStateWriteClosed)
	}
	if !errors.Is(repeatedResult.Err, sendErr) || repeatedResult.Forced {
		t.Fatalf("repeated shutdown result = %+v, want retained %v", repeatedResult, sendErr)
	}
	observation := stream.observe()
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("ReportState send failure observation = %+v, want serialized single close", observation)
	}
	assertStreamEvents(t, observation.events, []string{
		"send:start:1", "send:end:1", "close_send:start:1", "close_send:end:1",
	})
}

func TestWorkerJoinsReportDaemon_AfterCloseAndStreamCancellation(t *testing.T) {
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
	baseStream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{send: 1, recv: 1, closeSend: 1})
	stream := &delayedRecvExitReportStateStream{
		NezhaService_ReportSystemStateClient: baseStream,
		recvReleased:                         make(chan struct{}),
		allowExit:                            make(chan struct{}),
	}
	session.bindReportState(reportSession, stream)
	session.startDaemon(func() { reportStateDaemon(reportSession, session.signalExit) })
	baseStream.waitWriteEntered(t, streamWriteSend)
	baseStream.releaseWrite(streamWriteSend, nil)
	baseStream.waitRecvEntered(t)
	graceContext, cancelGrace := context.WithCancel(context.Background())
	shutdownExited := make(chan struct{})
	go func() {
		session.stopAndWait(graceContext, errors.New("graceful report shutdown"))
		close(shutdownExited)
	}()
	baseStream.waitWriteEntered(t, streamWriteCloseSend)

	// When
	baseStream.releaseWrite(streamWriteCloseSend, nil)
	cancelGrace()
	awaitStreamSignal(t, stream.recvReleased, "ReportState Recv cancellation")
	select {
	case <-shutdownExited:
		t.Fatal("worker shutdown completed before ReportState daemon exit")
	default:
	}
	close(stream.allowExit)
	awaitStreamSignal(t, shutdownExited, "worker shutdown after ReportState daemon exit")

	// Then
	observation := baseStream.observe()
	assertStreamEvents(t, observation.events, []string{
		"send:start:1", "send:end:1", "recv:start:1",
		"close_send:start:1", "close_send:end:1", "recv:canceled:1",
	})
	if observation.maxWriteInFlight != 1 || observation.closeSendCount != 1 {
		t.Fatalf("ReportState shutdown observation = %+v, want serialized single close", observation)
	}
	t.Log("event order: send end -> CloseSend once -> stream cancel -> Recv exit -> daemon join")
}

func TestWorkerJoinsReportDaemon_AfterForcedBlockedSendCancellation(t *testing.T) {
	// Given
	originalSnapshot := runtimeConfigSnapshot.Load()
	originalDependencies := reportMonitorDependencies
	originalInitialized := initialized
	t.Cleanup(func() {
		runtimeConfigSnapshot.Store(originalSnapshot)
		reportMonitorDependencies = originalDependencies
		initialized = originalInitialized
	})
	publishRuntimeConfig(model.AgentConfig{ReportDelay: 60})
	reportMonitorDependencies.trackNetworkSpeed = func(*model.AgentConfig) {}
	reportMonitorDependencies.getState = func(*model.AgentConfig, bool, bool) *model.HostState {
		return &model.HostState{}
	}
	initialized = true

	session := newConnectionSession(context.Background())
	reportSession := session.newReportStateSession()
	stream := newContextBlockedReportStateStream(reportSession.streamContext)
	session.bindReportState(reportSession, stream)
	session.startDaemon(func() { reportStateDaemon(reportSession, session.signalExit) })
	awaitStreamSignal(t, stream.sendStarted, "worker context-blocked ReportState Send entry")
	graceContext, cancelGrace := context.WithCancel(context.Background())
	workerExited := make(chan struct{})
	go func() {
		session.stopAndWait(graceContext, context.Canceled)
		close(workerExited)
	}()

	// When
	cancelGrace()
	awaitStreamSignal(t, workerExited, "forced ReportState worker shutdown")

	// Then
	events, maxInFlight, closeCount, contextLiveAtClose := stream.observation()
	assertStreamEvents(t, events, []string{"send:start", "stream:cancel", "send:context_done", "close:start", "close:end"})
	if maxInFlight != 1 || closeCount != 1 || contextLiveAtClose {
		t.Fatalf("forced worker writes: max=%d close=%d liveAtClose=%t", maxInFlight, closeCount, contextLiveAtClose)
	}
	t.Log("forced event order: stream cancel -> Send exit -> CloseSend once -> daemon join")
}
