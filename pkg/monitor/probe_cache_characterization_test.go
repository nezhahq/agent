package monitor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

func TestTryHostStopsAfterMaximumFailedProbeAttempts(t *testing.T) {
	// Given
	originalAttempts := hostDataFetchAttempts[CPU]
	hostDataFetchAttempts[CPU] = 0
	t.Cleanup(func() { hostDataFetchAttempts[CPU] = originalAttempts })
	calls := 0
	probeError := errors.New("host probe failed")
	probe := func(context.Context) ([]string, error) {
		calls++
		return nil, probeError
	}

	// When
	for range maxDeviceDataFetchAttempts + 1 {
		tryHost(context.Background(), CPU, probe)
	}

	// Then
	if calls != maxDeviceDataFetchAttempts {
		t.Fatalf("host probe calls = %d, want %d", calls, maxDeviceDataFetchAttempts)
	}
	if hostDataFetchAttempts[CPU] != maxDeviceDataFetchAttempts {
		t.Fatalf("host failure cache = %d, want %d", hostDataFetchAttempts[CPU], maxDeviceDataFetchAttempts)
	}
}

func TestTryStatSuccessClearsFailedProbeAttempts(t *testing.T) {
	// Given
	stateLock.Lock()
	originalAttempts := statDataFetchAttempts[CPU]
	statDataFetchAttempts[CPU] = 2
	stateLock.Unlock()
	t.Cleanup(func() {
		stateLock.Lock()
		statDataFetchAttempts[CPU] = originalAttempts
		stateLock.Unlock()
	})
	probe := func(context.Context) ([]float64, error) {
		return []float64{42.5}, nil
	}

	// When
	result := tryStat(context.Background(), CPU, probe)

	// Then
	if len(result) != 1 || result[0] != 42.5 {
		t.Fatalf("state probe result = %v, want [42.5]", result)
	}
	stateLock.Lock()
	attempts := statDataFetchAttempts[CPU]
	stateLock.Unlock()
	if attempts != 0 {
		t.Fatalf("state failure cache = %d, want reset to zero", attempts)
	}
}

func TestTrackNetworkSpeedPreservesTransferAndSpeedFormula(t *testing.T) {
	// Given
	originalProbe := nicStateProbe
	originalNow := networkNow
	metricLock.Lock()
	originalNetInSpeed, originalNetOutSpeed := netInSpeed, netOutSpeed
	originalNetInTransfer, originalNetOutTransfer := netInTransfer, netOutTransfer
	originalLastUpdate := lastUpdateNetStats
	netInTransfer, netOutTransfer, lastUpdateNetStats = 1000, 2000, 100
	metricLock.Unlock()
	nicStateProbe = func(context.Context) ([]uint64, error) {
		return []uint64{1400, 2600}, nil
	}
	networkNow = func() time.Time { return time.Unix(104, 0) }
	t.Cleanup(func() {
		nicStateProbe = originalProbe
		networkNow = originalNow
		metricLock.Lock()
		netInSpeed, netOutSpeed = originalNetInSpeed, originalNetOutSpeed
		netInTransfer, netOutTransfer = originalNetInTransfer, originalNetOutTransfer
		lastUpdateNetStats = originalLastUpdate
		metricLock.Unlock()
	})

	// When
	TrackNetworkSpeed(&model.AgentConfig{})

	// Then
	metricLock.RLock()
	defer metricLock.RUnlock()
	if netInTransfer != 1400 || netOutTransfer != 2600 {
		t.Fatalf("network transfers = in:%d out:%d, want in:1400 out:2600", netInTransfer, netOutTransfer)
	}
	if netInSpeed != 100 || netOutSpeed != 150 {
		t.Fatalf("network speeds = in:%d out:%d, want delta/time in:100 out:150", netInSpeed, netOutSpeed)
	}
	if lastUpdateNetStats != 104 {
		t.Fatalf("last network update = %d, want 104", lastUpdateNetStats)
	}
}
