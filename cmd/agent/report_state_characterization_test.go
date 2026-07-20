package main

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nezhahq/agent/model"
)

func TestReportStateDaemon_PreservesConfiguredCadenceAndReceipts(t *testing.T) {
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

		publishRuntimeConfig(model.AgentConfig{ReportDelay: 7, IPReportPeriod: 600})
		reportMonitorDependencies.trackNetworkSpeed = func(*model.AgentConfig) {}
		reportMonitorDependencies.getState = func(*model.AgentConfig, bool, bool) *model.HostState {
			return &model.HostState{}
		}
		initialized = true
		geoipReported = true
		lastReportHostInfo = time.Now().Add(time.Hour)
		lastReportIPInfo = time.Now().Add(time.Hour)
		reportSession := newReportStateSession(context.Background())
		stream := newReportSystemStateStreamFixture(reportSession.streamContext, streamCallAllowance{send: 2, recv: 2})
		reportSession.bind(stream)
		daemonExited := make(chan struct{})
		go func() {
			reportStateDaemon(reportSession, func(error) { close(daemonExited) })
		}()

		// When
		<-stream.writeEntered
		stream.releaseWrite(streamWriteSend, nil)
		<-stream.recvEntered
		stream.releaseRecv(nil, nil)
		time.Sleep(6 * time.Second)
		synctest.Wait()

		// Then
		select {
		case operation := <-stream.writeEntered:
			t.Fatalf("report cadence fired before configured delay: %s", operation)
		default:
		}
		time.Sleep(time.Second)
		<-stream.writeEntered
		stream.releaseWrite(streamWriteSend, nil)
		<-stream.recvEntered
		stream.releaseRecv(nil, errors.New("stop characterization daemon"))
		<-daemonExited

		observation := stream.observe()
		assertStreamEvents(t, observation.events, []string{
			"send:start:1", "send:end:1", "recv:start:1", "recv:end:1",
			"send:start:2", "send:end:2", "recv:start:2", "recv:end:2",
		})
		if len(stream.sentMessages()) != 2 {
			t.Fatalf("state sends = %d, want 2", len(stream.sentMessages()))
		}
	})
}
