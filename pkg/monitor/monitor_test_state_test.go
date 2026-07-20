package monitor

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	psLoad "github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/nezhahq/agent/model"
)

type monitorProbeSnapshot struct {
	hostInfo          func() (*host.InfoStat, error)
	virtualMemory     func() (*mem.VirtualMemoryStat, error)
	cpuHost           hostStateFunc[[]string]
	cpuState          hostStateFunc[[]float64]
	diskHost          hostStateFunc[uint64]
	diskState         hostStateFunc[uint64]
	gpuHost           hostStateFunc[[]string]
	gpuState          hostStateFunc[[]float64]
	loadState         hostStateFunc[*psLoad.AvgStat]
	nicState          hostStateFunc[[]uint64]
	temperature       hostStateFunc[[]model.SensorTemperature]
	fetchIP           func([]string, bool) string
	temperatureUpdate func()
}

type monitorMetricStateSnapshot struct {
	netInSpeed         uint64
	netOutSpeed        uint64
	netInTransfer      uint64
	netOutTransfer     uint64
	lastUpdateNetStats uint64
	cachedBootTime     time.Time
	temperatureStat    []model.SensorTemperature
	updateTempStatus   bool
	hostAttempts       map[uint8]uint8
	statAttempts       map[uint8]uint8
	retryTimes         int
	failedStartedAt    time.Time
	latestRetryAt      time.Time
	geoQueryIP         string
	countryCode        string
	geoIPChanged       bool
}

type monitorTestStateSnapshot struct {
	probes  monitorProbeSnapshot
	metrics monitorMetricStateSnapshot
}

func captureMonitorTestState() monitorTestStateSnapshot {
	geoIPFetchLock.Lock()
	defer geoIPFetchLock.Unlock()
	hostLock.Lock()
	defer hostLock.Unlock()
	stateLock.Lock()
	defer stateLock.Unlock()
	metricLock.Lock()
	defer metricLock.Unlock()
	temperatureLock.Lock()
	defer temperatureLock.Unlock()
	geoIPLock.Lock()
	defer geoIPLock.Unlock()

	return monitorTestStateSnapshot{
		probes: monitorProbeSnapshot{
			hostInfo: hostInfoProbe, virtualMemory: virtualMemoryProbe,
			cpuHost: cpuHostProbe, cpuState: cpuStateProbe,
			diskHost: diskHostProbe, diskState: diskStateProbe,
			gpuHost: gpuHostProbe, gpuState: gpuStateProbe,
			loadState: loadStateProbe, nicState: nicStateProbe,
			temperature: temperatureProbe, fetchIP: fetchIPProbe,
			temperatureUpdate: temperatureUpdated,
		},
		metrics: monitorMetricStateSnapshot{
			netInSpeed: netInSpeed, netOutSpeed: netOutSpeed,
			netInTransfer: netInTransfer, netOutTransfer: netOutTransfer,
			lastUpdateNetStats: lastUpdateNetStats, cachedBootTime: cachedBootTime,
			temperatureStat: slices.Clone(temperatureStat), updateTempStatus: updateTempStatus.Load(),
			hostAttempts: maps.Clone(hostDataFetchAttempts), statAttempts: maps.Clone(statDataFetchAttempts),
			retryTimes: retryTimes, failedStartedAt: failedStartedAt, latestRetryAt: latestRetryAt,
			geoQueryIP: geoQueryIP, countryCode: countryCode, geoIPChanged: geoIPChanged,
		},
	}
}

func (s monitorTestStateSnapshot) restore() {
	geoIPFetchLock.Lock()
	defer geoIPFetchLock.Unlock()
	hostLock.Lock()
	defer hostLock.Unlock()
	stateLock.Lock()
	defer stateLock.Unlock()
	metricLock.Lock()
	defer metricLock.Unlock()
	temperatureLock.Lock()
	defer temperatureLock.Unlock()
	geoIPLock.Lock()
	defer geoIPLock.Unlock()

	hostInfoProbe, virtualMemoryProbe = s.probes.hostInfo, s.probes.virtualMemory
	cpuHostProbe, cpuStateProbe = s.probes.cpuHost, s.probes.cpuState
	diskHostProbe, diskStateProbe = s.probes.diskHost, s.probes.diskState
	gpuHostProbe, gpuStateProbe = s.probes.gpuHost, s.probes.gpuState
	loadStateProbe, nicStateProbe = s.probes.loadState, s.probes.nicState
	temperatureProbe, fetchIPProbe = s.probes.temperature, s.probes.fetchIP
	temperatureUpdated = s.probes.temperatureUpdate

	netInSpeed, netOutSpeed = s.metrics.netInSpeed, s.metrics.netOutSpeed
	netInTransfer, netOutTransfer = s.metrics.netInTransfer, s.metrics.netOutTransfer
	lastUpdateNetStats, cachedBootTime = s.metrics.lastUpdateNetStats, s.metrics.cachedBootTime
	temperatureStat = slices.Clone(s.metrics.temperatureStat)
	updateTempStatus.Store(s.metrics.updateTempStatus)
	hostDataFetchAttempts = maps.Clone(s.metrics.hostAttempts)
	statDataFetchAttempts = maps.Clone(s.metrics.statAttempts)
	retryTimes, failedStartedAt, latestRetryAt = s.metrics.retryTimes, s.metrics.failedStartedAt, s.metrics.latestRetryAt
	geoQueryIP, countryCode, geoIPChanged = s.metrics.geoQueryIP, s.metrics.countryCode, s.metrics.geoIPChanged
}

func TestMonitorTestStateSnapshotRestoresEveryBarrierGlobal(t *testing.T) {
	// Given
	original := captureMonitorTestState()
	t.Cleanup(original.restore)
	seed := monitorMetricStateSnapshot{
		netInSpeed: 11, netOutSpeed: 12, netInTransfer: 13, netOutTransfer: 14,
		lastUpdateNetStats: 15, cachedBootTime: time.Unix(16, 0),
		temperatureStat:  []model.SensorTemperature{{Name: "seed", Temperature: 17}},
		updateTempStatus: true,
		hostAttempts:     map[uint8]uint8{CPU: 1, GPU: 2},
		statAttempts:     map[uint8]uint8{CPU: 1, GPU: 2, Load: 3, Temperatures: 1},
		retryTimes:       2, failedStartedAt: time.Unix(18, 0), latestRetryAt: time.Unix(19, 0),
		geoQueryIP: "192.0.2.20", countryCode: "aa", geoIPChanged: false,
	}
	seedMonitorMetricState(seed)
	snapshot := captureMonitorTestState()
	seedMonitorMetricState(monitorMetricStateSnapshot{
		netInSpeed: 91, netOutSpeed: 92, netInTransfer: 93, netOutTransfer: 94,
		lastUpdateNetStats: 95, cachedBootTime: time.Unix(96, 0),
		temperatureStat:  []model.SensorTemperature{{Name: "mutated", Temperature: 97}},
		updateTempStatus: false,
		hostAttempts:     map[uint8]uint8{CPU: 3, GPU: 3},
		statAttempts:     map[uint8]uint8{CPU: 3, GPU: 3, Load: 3, Temperatures: 3},
		retryTimes:       4, failedStartedAt: time.Unix(98, 0), latestRetryAt: time.Unix(99, 0),
		geoQueryIP: "2001:db8::99", countryCode: "zz", geoIPChanged: true,
	})

	// When
	snapshot.restore()

	// Then
	assertMonitorMetricState(t, seed)
}

func seedMonitorMetricState(state monitorMetricStateSnapshot) {
	geoIPFetchLock.Lock()
	defer geoIPFetchLock.Unlock()
	hostLock.Lock()
	defer hostLock.Unlock()
	stateLock.Lock()
	defer stateLock.Unlock()
	metricLock.Lock()
	defer metricLock.Unlock()
	temperatureLock.Lock()
	defer temperatureLock.Unlock()
	geoIPLock.Lock()
	defer geoIPLock.Unlock()

	netInSpeed, netOutSpeed = state.netInSpeed, state.netOutSpeed
	netInTransfer, netOutTransfer = state.netInTransfer, state.netOutTransfer
	lastUpdateNetStats, cachedBootTime = state.lastUpdateNetStats, state.cachedBootTime
	temperatureStat = slices.Clone(state.temperatureStat)
	updateTempStatus.Store(state.updateTempStatus)
	hostDataFetchAttempts = maps.Clone(state.hostAttempts)
	statDataFetchAttempts = maps.Clone(state.statAttempts)
	retryTimes, failedStartedAt, latestRetryAt = state.retryTimes, state.failedStartedAt, state.latestRetryAt
	geoQueryIP, countryCode, geoIPChanged = state.geoQueryIP, state.countryCode, state.geoIPChanged
}

func assertMonitorMetricState(t *testing.T, want monitorMetricStateSnapshot) {
	t.Helper()
	got := captureMonitorTestState().metrics
	if got.netInSpeed != want.netInSpeed || got.netOutSpeed != want.netOutSpeed ||
		got.netInTransfer != want.netInTransfer || got.netOutTransfer != want.netOutTransfer ||
		got.lastUpdateNetStats != want.lastUpdateNetStats || !got.cachedBootTime.Equal(want.cachedBootTime) ||
		!slices.Equal(got.temperatureStat, want.temperatureStat) || got.updateTempStatus != want.updateTempStatus ||
		!maps.Equal(got.hostAttempts, want.hostAttempts) || !maps.Equal(got.statAttempts, want.statAttempts) ||
		got.retryTimes != want.retryTimes || !got.failedStartedAt.Equal(want.failedStartedAt) ||
		!got.latestRetryAt.Equal(want.latestRetryAt) || got.geoQueryIP != want.geoQueryIP ||
		got.countryCode != want.countryCode || got.geoIPChanged != want.geoIPChanged {
		t.Fatalf("restored monitor metric state = %+v, want %+v", got, want)
	}
}
