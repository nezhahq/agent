package monitor

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	psLoad "github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor/disk"
	"github.com/nezhahq/agent/pkg/monitor/nic"
)

func TestMonitorUsesCallerSnapshotAfterSourceMutationMidOperation(t *testing.T) {
	// Given
	sourceA := model.AgentConfig{
		GPU:                         true,
		Temperature:                 true,
		NICAllowlist:                map[string]bool{"nic-a": true},
		HardDrivePartitionAllowlist: []string{"/disk-a"},
		CustomIPApi:                 []string{"https://ip-a.example.test"},
	}
	snapshotAValue := sourceA.Clone()
	snapshotA := &snapshotAValue
	observed := installMonitorSnapshotProbeBarrier(t, snapshotA, func() {
		sourceA.NICAllowlist["nic-a"] = false
		sourceA.HardDrivePartitionAllowlist[0] = "/mutated"
		sourceA.CustomIPApi[0] = "https://mutated.example.test"
	})
	// When
	runMonitorOperation(snapshotA)
	observed.waitTemperatureUpdate()

	// Then
	if err := observed.validateGenerationA(snapshotA); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorSnapshotObservationRejectsMissingDiskAndIPProbes(t *testing.T) {
	// Given
	snapshot := &model.AgentConfig{
		NICAllowlist:                map[string]bool{"nic-a": true},
		HardDrivePartitionAllowlist: []string{"/disk-a"},
		CustomIPApi:                 []string{"https://ip-a.example.test"},
	}
	observation := &monitorSnapshotObservation{
		nicAllowlists:    []map[string]bool{{"nic-a": true}},
		gpuHostCalls:     1,
		gpuStateCalls:    1,
		temperatureCalls: 1,
		temperatureDone:  make(chan struct{}, 1),
	}
	observation.temperatureDone <- struct{}{}

	// When
	err := observation.validateGenerationA(snapshot)

	// Then
	if err == nil {
		t.Fatal("missing disk and IP probe calls must fail observation validation")
	}
}

type monitorSnapshotObservation struct {
	mu                 sync.Mutex
	nicAllowlists      []map[string]bool
	diskAllowlists     [][]string
	customEndpointSets [][]string
	gpuHostCalls       int
	gpuStateCalls      int
	temperatureCalls   int
	barrierCalls       int
	temperatureStarted bool
	temperatureJoined  bool
	temperatureDone    chan struct{}
}

func installMonitorSnapshotProbeBarrier(t *testing.T, snapshotA *model.AgentConfig, afterTrack func()) *monitorSnapshotObservation {
	t.Helper()
	originalState := captureMonitorTestState()
	observation := &monitorSnapshotObservation{temperatureDone: make(chan struct{}, 1)}

	hostInfoProbe = func() (*host.InfoStat, error) { return &host.InfoStat{}, nil }
	virtualMemoryProbe = func() (*mem.VirtualMemoryStat, error) { return &mem.VirtualMemoryStat{}, nil }
	cpuHostProbe = func(context.Context) ([]string, error) { return nil, nil }
	cpuStateProbe = func(context.Context) ([]float64, error) { return []float64{0}, nil }
	loadStateProbe = func(context.Context) (*psLoad.AvgStat, error) { return &psLoad.AvgStat{}, nil }
	nicStateProbe = func(ctx context.Context) ([]uint64, error) {
		allowlist, _ := ctx.Value(nic.NICKey).(map[string]bool)
		observation.recordNICAllowlist(allowlist)
		observation.mu.Lock()
		observation.barrierCalls++
		barrierCalls := observation.barrierCalls
		observation.mu.Unlock()
		if barrierCalls == 1 {
			afterTrack()
		}
		return []uint64{100, 200}, nil
	}
	diskHostProbe = func(ctx context.Context) (uint64, error) {
		observation.recordDiskAllowlist(ctx)
		return 300, nil
	}
	diskStateProbe = func(ctx context.Context) (uint64, error) {
		observation.recordDiskAllowlist(ctx)
		return 150, nil
	}
	gpuHostProbe = func(context.Context) ([]string, error) {
		observation.mu.Lock()
		observation.gpuHostCalls++
		observation.mu.Unlock()
		return []string{"gpu-a"}, nil
	}
	gpuStateProbe = func(context.Context) ([]float64, error) {
		observation.mu.Lock()
		observation.gpuStateCalls++
		observation.mu.Unlock()
		return []float64{25}, nil
	}
	temperatureProbe = func(context.Context) ([]model.SensorTemperature, error) {
		observation.mu.Lock()
		observation.temperatureCalls++
		observation.temperatureStarted = true
		observation.mu.Unlock()
		return []model.SensorTemperature{{Name: "temperature-a", Temperature: 42}}, nil
	}
	temperatureUpdated = func() { observation.temperatureDone <- struct{}{} }
	fetchIPProbe = func(servers []string, isV6 bool) string {
		observation.recordEndpoints(servers)
		if isV6 {
			return "2001:db8::9"
		}
		return "192.0.2.9"
	}
	geoIPLock.Lock()
	retryTimes, failedStartedAt, latestRetryAt = 0, time.Time{}, time.Time{}
	geoQueryIP, countryCode, geoIPChanged = "", "", true
	geoIPLock.Unlock()

	t.Cleanup(func() {
		observation.mu.Lock()
		temperatureStarted := observation.temperatureStarted
		temperatureJoined := observation.temperatureJoined
		barrierCalls := observation.barrierCalls
		observation.mu.Unlock()
		if temperatureStarted && !temperatureJoined {
			observation.waitTemperatureUpdate()
			temperatureJoined = true
		}
		if !temperatureJoined {
			t.Error("temperature update probe was not started and joined before cleanup")
		}
		originalState.restore()
		if barrierCalls != 1 {
			t.Errorf("NIC publication barrier calls = %d, want exactly 1", barrierCalls)
		}
	})
	return observation
}

func (o *monitorSnapshotObservation) waitTemperatureUpdate() {
	<-o.temperatureDone
	o.mu.Lock()
	o.temperatureJoined = true
	o.mu.Unlock()
}

func runMonitorOperation(config *model.AgentConfig) {
	TrackNetworkSpeed(config)
	GetState(config, true, true)
	GetHost(config)
	FetchIP(config, false)
}

func (o *monitorSnapshotObservation) recordNICAllowlist(allowlist map[string]bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.nicAllowlists = append(o.nicAllowlists, allowlist)
}

func (o *monitorSnapshotObservation) recordDiskAllowlist(ctx context.Context) {
	allowlist, _ := ctx.Value(disk.DiskKey).([]string)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.diskAllowlists = append(o.diskAllowlists, allowlist)
}

func (o *monitorSnapshotObservation) recordEndpoints(endpoints []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.customEndpointSets = append(o.customEndpointSets, endpoints)
}

func (o *monitorSnapshotObservation) validateGenerationA(snapshotA *model.AgentConfig) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.nicAllowlists) != 1 || !o.nicAllowlists[0]["nic-a"] || o.nicAllowlists[0]["nic-b"] {
		return fmt.Errorf("NIC allowlists = %v, want generation A %v", o.nicAllowlists, snapshotA.NICAllowlist)
	}
	if len(o.diskAllowlists) != 2 {
		return fmt.Errorf("disk probe calls = %d, want exactly 2", len(o.diskAllowlists))
	}
	for _, allowlist := range o.diskAllowlists {
		if !slices.Equal(allowlist, snapshotA.HardDrivePartitionAllowlist) {
			return fmt.Errorf("disk allowlist = %v, want generation A %v", allowlist, snapshotA.HardDrivePartitionAllowlist)
		}
	}
	if len(o.customEndpointSets) != 2 {
		return fmt.Errorf("IP endpoint probe calls = %d, want exactly 2", len(o.customEndpointSets))
	}
	for _, endpoints := range o.customEndpointSets {
		if !slices.Equal(endpoints, snapshotA.CustomIPApi) {
			return fmt.Errorf("custom endpoints = %v, want generation A %v", endpoints, snapshotA.CustomIPApi)
		}
	}
	if o.gpuHostCalls != 1 || o.gpuStateCalls != 1 || o.temperatureCalls != 1 {
		return fmt.Errorf("generation A feature probes = gpuHost:%d gpuState:%d temperature:%d, want 1 each", o.gpuHostCalls, o.gpuStateCalls, o.temperatureCalls)
	}
	return nil
}
