package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

func configureTCPReportDaemon(t *testing.T) {
	t.Helper()
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
}

func TestGRPCGracefulClose_StopAndWaitConsumesReportTerminal(t *testing.T) {
	// Given
	configureTCPReportDaemon(t)
	reportEOF := make(chan struct{}, 1)
	reportReady := make(chan struct{}, 1)
	requestEOF := make(chan struct{}, 1)
	releaseTerminal := make(chan struct{})
	service := &grpcTCPService{
		requestTask: func(stream pb.NezhaService_RequestTaskServer) error {
			if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
				return err
			}
			requestEOF <- struct{}{}
			return nil
		},
		reportSystemState: func(stream pb.NezhaService_ReportSystemStateServer) error {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(&pb.Receipt{}); err != nil {
				return err
			}
			reportReady <- struct{}{}
			if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
				return err
			}
			reportEOF <- struct{}{}
			<-releaseTerminal
			stream.SetTrailer(metadata.Pairs("x-grpc-lifecycle", "stop-ok"))
			return nil
		},
		ioStream: func(pb.NezhaService_IOStreamServer) error { return nil },
	}
	fixture := newGRPCTCPFixture(t, service)
	session := newConnectionSession(context.Background())
	requestStream, err := fixture.client.RequestTask(session.requestTaskContext)
	if err != nil {
		t.Fatalf("open RequestTask: %v", err)
	}
	requestSession := session.bindRequestTask(requestStream)
	session.startDaemon(func() { receiveTasksDaemon(requestSession, session) })
	reportSession, err := openReportState(session, fixture.client)
	if err != nil {
		t.Fatalf("open ReportSystemState: %v", err)
	}
	session.startDaemon(func() { reportStateDaemon(reportSession, session.signalExit) })
	awaitStreamSignal(t, reportReady, "ReportState initial receipt")
	shutdownDone := make(chan struct{})
	reconnected := make(chan struct{})
	grace, cancelGrace := context.WithTimeout(context.Background(), streamFixtureDeadline)
	defer cancelGrace()

	// When
	go func() {
		reconnectAfterSessionExit(session, sessionShutdown{graceContext: grace, cause: context.Canceled}, func() {
			close(reconnected)
		})
		close(shutdownDone)
	}()
	awaitStreamSignal(t, reportEOF, "ReportState client EOF")

	// Then
	if session.streamContext.Err() != nil {
		t.Fatalf("shared stream canceled before ReportState terminal: %v", session.streamContext.Err())
	}
	select {
	case <-shutdownDone:
		t.Fatal("stopAndWait returned before ReportState terminal")
	default:
	}
	close(releaseTerminal)
	awaitStreamSignal(t, shutdownDone, "stopAndWait after ReportState terminal")
	awaitStreamSignal(t, requestEOF, "RequestTask EOF after ReportState terminal")
	awaitStreamSignal(t, reconnected, "reconnect after stream terminal and joins")
	if !errors.Is(reportSession.terminalError(), io.EOF) {
		t.Fatalf("ReportState terminal error = %v, want io.EOF", reportSession.terminalError())
	}
	if got := reportSession.stream.Trailer().Get("x-grpc-lifecycle"); len(got) != 1 || got[0] != "stop-ok" {
		t.Fatalf("ReportState terminal trailer = %v, want stop-ok", got)
	}
	if session.longLivedStreamTasks.activeCount() != 0 {
		t.Fatalf("active registry = %d, want 0", session.longLivedStreamTasks.activeCount())
	}
	if !errors.Is(session.streamContext.Err(), context.Canceled) {
		t.Fatalf("shared stream context = %v, want canceled after ReportState terminal", session.streamContext.Err())
	}
}

func TestGRPCCancellation_StopAndWaitCancelsReportAfterGrace(t *testing.T) {
	// Given
	configureTCPReportDaemon(t)
	reportEOF := make(chan struct{}, 1)
	reportReady := make(chan struct{}, 1)
	serverCanceled := make(chan error, 1)
	service := &grpcTCPService{
		requestTask: func(pb.NezhaService_RequestTaskServer) error { return nil },
		reportSystemState: func(stream pb.NezhaService_ReportSystemStateServer) error {
			if _, err := stream.Recv(); err != nil {
				return err
			}
			if err := stream.Send(&pb.Receipt{}); err != nil {
				return err
			}
			reportReady <- struct{}{}
			if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
				return err
			}
			reportEOF <- struct{}{}
			<-stream.Context().Done()
			serverCanceled <- stream.Context().Err()
			return stream.Context().Err()
		},
		ioStream: func(pb.NezhaService_IOStreamServer) error { return nil },
	}
	fixture := newGRPCTCPFixture(t, service)
	session := newConnectionSession(context.Background())
	reportSession, err := openReportState(session, fixture.client)
	if err != nil {
		t.Fatalf("open ReportSystemState: %v", err)
	}
	session.startDaemon(func() { reportStateDaemon(reportSession, session.signalExit) })
	awaitStreamSignal(t, reportReady, "ReportState initial receipt before grace cancellation")
	grace, cancelGrace := context.WithCancel(context.Background())
	shutdownDone := make(chan struct{})
	go func() {
		session.stopAndWait(grace, context.Canceled)
		close(shutdownDone)
	}()
	awaitStreamSignal(t, reportEOF, "ReportState EOF before grace cancellation")

	// When
	cancelGrace()

	// Then
	awaitStreamSignal(t, shutdownDone, "ReportState grace cancellation")
	if err := awaitStreamOperationResult(t, serverCanceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReportState server context = %v, want context.Canceled", err)
	}
	if !errors.Is(reportSession.streamContext.Err(), context.Canceled) {
		t.Fatalf("ReportState child context = %v, want context.Canceled", reportSession.streamContext.Err())
	}
}
