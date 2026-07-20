package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func commitIntegratedReload(t *testing.T, generationA, generationB model.AgentConfig) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.yml")
	seed := []byte("server: server-a:5555\nclient_secret: secret-a\nuuid: 00000000-0000-0000-0000-00000000000a\n")
	if err := os.WriteFile(configPath, seed, 0o600); err != nil {
		t.Fatalf("seed integrated config: %v", err)
	}
	if err := agentConfig.Read(configPath); err != nil {
		t.Fatalf("read integrated generation A: %v", err)
	}
	agentConfig = mergeIntegratedGeneration(agentConfig, generationA)
	publishRuntimeConfig(agentConfig)
	pending := mergeIntegratedGeneration(agentConfig, generationB)
	if err := commitPendingRuntimeConfig(pending, func() {}, func() {}); err != nil {
		t.Fatalf("commit integrated generation B: %v", err)
	}
	if generation, err := classifyIntegratedConfig(loadRuntimeConfig()); err != nil || generation != integratedGenerationB {
		t.Fatalf("valid reload did not publish generation B: generation=%s err=%v", generation, err)
	}
	var persisted model.AgentConfig
	if err := persisted.Read(configPath); err != nil {
		t.Fatalf("parse integrated persisted config: %v", err)
	}
	if generation, err := classifyIntegratedConfig(&persisted); err != nil || generation != integratedGenerationB {
		t.Fatalf("persisted config is not complete generation B: generation=%s err=%v", generation, err)
	}
	if err := persisted.Save(); err != nil {
		t.Fatalf("persisted config lost its Save path state: %v", err)
	}
	var reloaded model.AgentConfig
	if err := reloaded.Read(configPath); err != nil {
		t.Fatalf("re-read integrated persisted config: %v", err)
	}
	if generation, err := classifyIntegratedConfig(&reloaded); err != nil || generation != integratedGenerationB {
		t.Fatalf("re-saved config is not complete generation B: generation=%s err=%v", generation, err)
	}
}

func mergeIntegratedGeneration(fileBacked, generation model.AgentConfig) model.AgentConfig {
	fileBacked.Server = generation.Server
	fileBacked.ClientSecret = generation.ClientSecret
	fileBacked.UUID = generation.UUID
	fileBacked.TLS = generation.TLS
	fileBacked.InsecureTLS = generation.InsecureTLS
	fileBacked.DNS = generation.DNS
	fileBacked.ReportDelay = generation.ReportDelay
	fileBacked.IPReportPeriod = generation.IPReportPeriod
	fileBacked.SkipConnectionCount = generation.SkipConnectionCount
	fileBacked.SkipProcsCount = generation.SkipProcsCount
	fileBacked.UseIPv6CountryCode = generation.UseIPv6CountryCode
	fileBacked.DisableForceUpdate = generation.DisableForceUpdate
	fileBacked.DisableCommandExecute = generation.DisableCommandExecute
	fileBacked.DisableNat = generation.DisableNat
	fileBacked.DisableSendQuery = generation.DisableSendQuery
	fileBacked.GPU = generation.GPU
	fileBacked.Temperature = generation.Temperature
	fileBacked.HardDrivePartitionAllowlist = generation.HardDrivePartitionAllowlist
	fileBacked.NICAllowlist = generation.NICAllowlist
	fileBacked.CustomIPApi = generation.CustomIPApi
	return fileBacked
}

func installIntegratedMonitorDependencies(t *testing.T, recorder *integratedMonitorRecorder) {
	t.Helper()
	reportMonitorDependencies = reportMonitorDependencySet{
		trackNetworkSpeed: func(config *model.AgentConfig) { recorder.record("track", config) },
		getState: func(config *model.AgentConfig, skipConnectionCount, skipProcsCount bool) *model.HostState {
			recorder.recordState(config, skipConnectionCount, skipProcsCount)
			return &model.HostState{}
		},
		getHost: func(config *model.AgentConfig) *model.Host {
			recorder.record("host", config)
			return &model.Host{}
		},
		fetchIP: func(config *model.AgentConfig, useIPv6CountryCode bool) *pb.GeoIP {
			recorder.recordFetch(config, useIPv6CountryCode)
			return &pb.GeoIP{Ip: &pb.IP{Ipv4: "192.0.2.10"}}
		},
		geoIPChanged:      func() bool { return true },
		markGeoIPReported: func(string) {},
	}
	client = &snapshotReportClient{}
	initialized = true
}

func restoreIntegratedRaceGlobals(t *testing.T) {
	t.Helper()
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	originalDependencies := reportMonitorDependencies
	originalClient, originalInitialized := client, initialized
	originalGeoIPReported := geoipReported
	originalDashboardBootTime := prevDashboardBootTime
	t.Cleanup(func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		reportMonitorDependencies = originalDependencies
		client = originalClient
		initialized = originalInitialized
		geoipReported = originalGeoIPReported
		prevDashboardBootTime = originalDashboardBootTime
	})
}
