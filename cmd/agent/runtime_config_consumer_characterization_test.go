package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestRuntimeConfigConsumerStartupDecisionsRemainStartupOnly(t *testing.T) {
	// Given
	restoreRuntimeConfigSnapshot(t)
	a := model.AgentConfig{Debug: false, DisableAutoUpdate: false, SelfUpdatePeriod: 17}
	b := model.AgentConfig{Debug: true, DisableAutoUpdate: true, SelfUpdatePeriod: 29}
	view := startupConfigViewFrom(publishRuntimeConfig(a))

	// When
	publishRuntimeConfig(b)

	// Then
	if view.debug || view.disableAutoUpdate || view.selfUpdatePeriod != 17 {
		t.Fatalf("startup view changed after publish: %+v", view)
	}
}

func TestTaskGateSnapshotObservesLatestConfigPerTask(t *testing.T) {
	// Given
	restoreRuntimeConfigSnapshot(t)
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "visible"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	request, err := json.Marshal(model.FsListRequest{Path: directory})
	if err != nil {
		t.Fatal(err)
	}
	task := &pb.Task{Type: model.TaskTypeFsList, Data: string(request)}
	a := model.AgentConfig{DisableCommandExecute: false, DisableNat: false}
	b := model.AgentConfig{DisableCommandExecute: true, DisableNat: true}
	publishRuntimeConfig(a)

	// When
	first := doTask(task)
	publishRuntimeConfig(b)
	second := doTask(task)

	// Then
	if first == nil || !first.Successful {
		t.Fatalf("first task result = %+v, want generation A permission", first)
	}
	if second == nil || !second.Successful {
		t.Fatalf("second task result = %+v, want structured generation B rejection", second)
	}
	var response model.FsListResult
	if err := json.Unmarshal([]byte(second.Data), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error != "agent disabled file operations" {
		t.Fatalf("second task response = %+v, want latest generation B gate", response)
	}
}

func TestDNSAndReportSnapshotsReloadPerIteration(t *testing.T) {
	// Given
	restoreRuntimeConfigSnapshot(t)
	original := agentConfig
	t.Cleanup(func() { agentConfig = original })
	a := model.AgentConfig{DNS: []string{"127.0.0.1:5301"}, ReportDelay: 1, IPReportPeriod: 31}
	b := model.AgentConfig{DNS: []string{"127.0.0.1:5302"}, ReportDelay: 2, IPReportPeriod: 47}
	agentConfig = a
	publishRuntimeConfig(a)

	// When
	dnsA := dnsConfigTupleFrom(loadRuntimeConfig())
	reportA := reportConfigTupleFrom(loadRuntimeConfig())
	agentConfig = b
	publishRuntimeConfig(b)
	dnsB := dnsConfigTupleFrom(loadRuntimeConfig())
	reportB := reportConfigTupleFrom(loadRuntimeConfig())

	// Then
	if !slices.Equal(dnsA.servers, a.DNS) || reportA.reportDelay != a.ReportDelay || reportA.ipReportPeriod != a.IPReportPeriod {
		t.Fatalf("first iteration DNS/report = %+v %+v, want A", dnsA, reportA)
	}
	if !slices.Equal(dnsB.servers, b.DNS) || reportB.reportDelay != b.ReportDelay || reportB.ipReportPeriod != b.IPReportPeriod {
		t.Fatalf("second iteration DNS/report = %+v %+v, want B", dnsB, reportB)
	}
}

func TestRuntimeConfigConsumerNilSnapshotReturnsEmptyConfig(t *testing.T) {
	// Given
	original := runtimeConfigSnapshot.Load()
	runtimeConfigSnapshot.Store(nil)
	t.Cleanup(func() { runtimeConfigSnapshot.Store(original) })

	// When
	config := loadRuntimeConfig()

	// Then
	if config != &emptyRuntimeConfig {
		t.Fatalf("nil runtime snapshot fallback = %+v, want non-nil empty config", config)
	}
}

func TestRuntimeConfigConsumersObserveOnlyCompleteGenerationsDuringRapidPublish(t *testing.T) {
	// Given
	restoreRuntimeConfigSnapshot(t)
	a := model.AgentConfig{
		DNS: []string{"127.0.0.1:5301"}, ReportDelay: 1, IPReportPeriod: 31,
		SkipConnectionCount: true, SkipProcsCount: true,
	}
	b := model.AgentConfig{
		DNS: []string{"127.0.0.1:5302"}, ReportDelay: 4, IPReportPeriod: 47,
		UseIPv6CountryCode: true, DisableCommandExecute: true, DisableNat: true,
		DisableSendQuery: true, DisableForceUpdate: true, UseAtomGitToUpgrade: true,
	}
	publishRuntimeConfig(a)
	const rounds = 1000

	// When
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for index := range rounds {
			if index%2 == 0 {
				publishRuntimeConfig(a)
			} else {
				publishRuntimeConfig(b)
			}
		}
	}()
	observations := make(chan runtimeConsumerObservation, rounds)
	go func() {
		defer wait.Done()
		for range rounds {
			config := loadRuntimeConfig()
			observations <- runtimeConsumerObservation{
				dns:    dnsConfigTupleFrom(config),
				report: reportConfigTupleFrom(config),
				task:   taskFeatureGatesFrom(config),
				update: updateConfigTupleFrom(config),
			}
		}
	}()
	wait.Wait()
	close(observations)

	// Then
	for observed := range observations {
		if !runtimeConsumerObservationMatches(observed, a) && !runtimeConsumerObservationMatches(observed, b) {
			t.Fatalf("mixed runtime consumer generation: %+v", observed)
		}
	}
}

func TestRuntimeConfigConsumerManualQACompleteGenerationTuples(t *testing.T) {
	// Given
	restoreRuntimeConfigSnapshot(t)
	a := model.AgentConfig{DNS: []string{"dns-a"}, ReportDelay: 1, IPReportPeriod: 31, SkipConnectionCount: true}
	b := model.AgentConfig{DNS: []string{"dns-b"}, ReportDelay: 4, IPReportPeriod: 47, UseIPv6CountryCode: true, DisableCommandExecute: true}

	// When
	configA := publishRuntimeConfig(a)
	observedA := observeRuntimeConsumers(configA)
	configB := publishRuntimeConfig(b)
	observedB := observeRuntimeConsumers(configB)

	// Then
	if !runtimeConsumerObservationMatches(observedA, a) || !runtimeConsumerObservationMatches(observedB, b) {
		t.Fatalf("manual QA observations are incomplete: A=%+v B=%+v", observedA, observedB)
	}
	t.Logf("generation A: dns=%v report={delay:%d ipPeriod:%d skipConn:%t skipProcs:%t use6:%t} task={commandDisabled:%t natDisabled:%t queryDisabled:%t forceUpdateDisabled:%t}", observedA.dns.servers, observedA.report.reportDelay, observedA.report.ipReportPeriod, observedA.report.skipConnectionCount, observedA.report.skipProcsCount, observedA.report.useIPv6CountryCode, observedA.task.disableCommandExecute, observedA.task.disableNat, observedA.task.disableSendQuery, observedA.task.disableForceUpdate)
	t.Logf("generation B: dns=%v report={delay:%d ipPeriod:%d skipConn:%t skipProcs:%t use6:%t} task={commandDisabled:%t natDisabled:%t queryDisabled:%t forceUpdateDisabled:%t}", observedB.dns.servers, observedB.report.reportDelay, observedB.report.ipReportPeriod, observedB.report.skipConnectionCount, observedB.report.skipProcsCount, observedB.report.useIPv6CountryCode, observedB.task.disableCommandExecute, observedB.task.disableNat, observedB.task.disableSendQuery, observedB.task.disableForceUpdate)
}

type runtimeConsumerObservation struct {
	dns    dnsConfigTuple
	report reportConfigTuple
	task   taskFeatureGates
	update updateConfigTuple
}

func observeRuntimeConsumers(config *model.AgentConfig) runtimeConsumerObservation {
	return runtimeConsumerObservation{
		dns:    dnsConfigTupleFrom(config),
		report: reportConfigTupleFrom(config),
		task:   taskFeatureGatesFrom(config),
		update: updateConfigTupleFrom(config),
	}
}

func runtimeConsumerObservationMatches(observed runtimeConsumerObservation, config model.AgentConfig) bool {
	return slices.Equal(observed.dns.servers, config.DNS) &&
		observed.report.reportDelay == config.ReportDelay &&
		observed.report.ipReportPeriod == config.IPReportPeriod &&
		observed.report.skipConnectionCount == config.SkipConnectionCount &&
		observed.report.skipProcsCount == config.SkipProcsCount &&
		observed.report.useIPv6CountryCode == config.UseIPv6CountryCode &&
		observed.task == taskFeatureGatesFromConfig(config) &&
		observed.update == updateConfigTupleFrom(&config)
}
