package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestDNSConfigTupleSnapshotRemainsCompleteWhenPublishingBMidOperation(t *testing.T) {
	// Given
	a := model.AgentConfig{DNS: []string{"127.0.0.1:5301"}}
	b := model.AgentConfig{}
	installRuntimeConfigConsumerBarrier(t, "dns", func() {
		agentConfig = b
		publishRuntimeConfig(b)
	})
	agentConfig = a
	config := publishRuntimeConfig(a)

	// When
	got := dnsConfigTupleFrom(config)

	// Then
	if got.configured != true || !slices.Equal(got.servers, a.DNS) {
		t.Fatalf("DNS tuple = configured:%t servers:%v, want complete generation A", got.configured, got.servers)
	}
}

func TestReportConfigTupleSnapshotRemainsCompleteWhenPublishingBMidOperation(t *testing.T) {
	// Given
	a := model.AgentConfig{ReportDelay: 1, IPReportPeriod: 31, SkipConnectionCount: true, SkipProcsCount: true}
	b := model.AgentConfig{ReportDelay: 4, IPReportPeriod: 47, UseIPv6CountryCode: true}
	installRuntimeConfigConsumerBarrier(t, "report", func() {
		agentConfig = b
		publishRuntimeConfig(b)
	})
	agentConfig = a
	config := publishRuntimeConfig(a)

	// When
	got := reportConfigTupleFrom(config)

	// Then
	if got.reportDelay != a.ReportDelay || got.ipReportPeriod != a.IPReportPeriod ||
		got.skipConnectionCount != a.SkipConnectionCount || got.skipProcsCount != a.SkipProcsCount ||
		got.useIPv6CountryCode != a.UseIPv6CountryCode {
		t.Fatalf("report tuple = %+v, want complete generation A", got)
	}
}

func TestTaskGateSnapshotRemainsCompleteWhenPublishingBMidOperation(t *testing.T) {
	// Given
	a := model.AgentConfig{DisableCommandExecute: false, DisableSendQuery: false}
	b := model.AgentConfig{DisableForceUpdate: true, DisableCommandExecute: true, DisableNat: true, DisableSendQuery: true}
	installRuntimeConfigConsumerBarrier(t, "task", func() {
		agentConfig = b
		publishRuntimeConfig(b)
	})
	agentConfig = a
	config := publishRuntimeConfig(a)

	// When
	got := taskFeatureGatesFrom(config)

	// Then
	want := taskFeatureGatesFromConfig(a)
	if got != want {
		t.Fatalf("task gates = %+v, want complete generation A %+v", got, want)
	}
}

func TestTaskGateSnapshotKeepsOneGenerationForWholeTask(t *testing.T) {
	// Given
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "visible"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := model.AgentConfig{DisableCommandExecute: false}
	b := model.AgentConfig{DisableCommandExecute: true}
	installRuntimeConfigConsumerBarrier(t, "task", func() {
		agentConfig = b
		publishRuntimeConfig(b)
	})
	agentConfig = a
	publishRuntimeConfig(a)
	request, err := json.Marshal(model.FsListRequest{Path: directory})
	if err != nil {
		t.Fatal(err)
	}

	// When
	result := doTask(&pb.Task{Type: model.TaskTypeFsList, Data: string(request)})

	// Then
	if result == nil || !result.Successful {
		t.Fatalf("task result = %+v, want generation A permission to remain active", result)
	}
	var response model.FsListResult
	if err := json.Unmarshal([]byte(result.Data), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Entries) != 1 || response.Entries[0].Name != "visible" {
		t.Fatalf("fs.list response = %+v, want complete generation A execution", response)
	}
}

func installRuntimeConfigConsumerBarrier(t *testing.T, boundary string, publish func()) {
	t.Helper()
	originalConfig := agentConfig
	originalBarrier := runtimeConfigConsumerBarrier
	originalSnapshot := runtimeConfigSnapshot.Load()
	targetCalls := 0
	unexpectedCalls := []string{}
	runtimeConfigConsumerBarrier = func(got string) {
		if got != boundary {
			unexpectedCalls = append(unexpectedCalls, got)
			return
		}
		targetCalls++
		if targetCalls == 1 {
			publish()
		}
	}
	t.Cleanup(func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		runtimeConfigConsumerBarrier = originalBarrier
		if err := validateRuntimeConfigBarrierCalls(boundary, targetCalls, unexpectedCalls); err != nil {
			t.Error(err)
		}
	})
}

func TestRuntimeConfigConsumerBarrierValidationRejectsMissingAndDoubleCalls(t *testing.T) {
	// Given
	testCases := []struct {
		name  string
		calls int
	}{
		{name: "missing", calls: 0},
		{name: "double", calls: 2},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// When
			err := validateRuntimeConfigBarrierCalls("task", testCase.calls, nil)

			// Then
			if err == nil {
				t.Fatalf("barrier validation accepted %d calls, want rejection", testCase.calls)
			}
		})
	}
}

func validateRuntimeConfigBarrierCalls(boundary string, targetCalls int, unexpectedCalls []string) error {
	if targetCalls != 1 {
		return fmt.Errorf("runtime config barrier %q fired %d times, want exactly once", boundary, targetCalls)
	}
	if len(unexpectedCalls) != 0 {
		return fmt.Errorf("runtime config barrier %q observed unexpected boundaries %v", boundary, unexpectedCalls)
	}
	return nil
}

func taskFeatureGatesFromConfig(config model.AgentConfig) taskFeatureGates {
	return taskFeatureGates{
		disableForceUpdate:    config.DisableForceUpdate,
		disableCommandExecute: config.DisableCommandExecute,
		disableNat:            config.DisableNat,
		disableSendQuery:      config.DisableSendQuery,
	}
}
