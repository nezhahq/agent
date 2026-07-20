package monitor

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor/disk"
	"github.com/nezhahq/agent/pkg/monitor/nic"
)

func TestMonitorUsesAuthoritativeSnapshotReferenceFields(t *testing.T) {
	// Given
	source := model.AgentConfig{
		HardDrivePartitionAllowlist: []string{"/data"},
		NICAllowlist:                map[string]bool{"eth0": true},
		CustomIPApi:                 []string{"https://ip.example.test"},
	}
	snapshotValue := source.Clone()
	snapshot := &snapshotValue
	originalNICProbe := nicStateProbe
	originalDiskHostProbe := diskHostProbe
	originalFetchIPProbe := fetchIPProbe
	var observedNIC map[string]bool
	var observedDisk []string
	var observedEndpoints [][]string
	var observedEndpointsLock sync.Mutex
	nicStateProbe = func(ctx context.Context) ([]uint64, error) {
		observedNIC, _ = ctx.Value(nic.NICKey).(map[string]bool)
		return []uint64{1, 2}, nil
	}
	diskHostProbe = func(ctx context.Context) (uint64, error) {
		observedDisk, _ = ctx.Value(disk.DiskKey).([]string)
		return 3, nil
	}
	fetchIPProbe = func(endpoints []string, isV6 bool) string {
		observedEndpointsLock.Lock()
		defer observedEndpointsLock.Unlock()
		observedEndpoints = append(observedEndpoints, endpoints)
		if isV6 {
			return "2001:db8::3"
		}
		return "192.0.2.3"
	}
	t.Cleanup(func() {
		nicStateProbe = originalNICProbe
		diskHostProbe = originalDiskHostProbe
		fetchIPProbe = originalFetchIPProbe
	})
	source.HardDrivePartitionAllowlist[0] = "/mutated"
	source.NICAllowlist["eth0"] = false
	source.CustomIPApi[0] = "https://mutated.example.test"

	// When
	TrackNetworkSpeed(snapshot)
	getDiskTotal(snapshot)
	FetchIP(snapshot, false)

	// Then
	if !observedNIC["eth0"] {
		t.Fatal("NIC probe did not receive the authoritative snapshot map")
	}
	if !slices.Equal(observedDisk, []string{"/data"}) {
		t.Fatalf("disk probe allowlist = %v, want [/data]", observedDisk)
	}
	for _, endpoints := range observedEndpoints {
		if !slices.Equal(endpoints, []string{"https://ip.example.test"}) {
			t.Fatalf("IP probe endpoints = %v, want authoritative snapshot endpoints", endpoints)
		}
	}
}

func TestMonitorNilSnapshotPreservesExistingEmptyBehavior(t *testing.T) {
	// Given
	originalNICProbe := nicStateProbe
	originalDiskStateProbe := diskStateProbe
	var observedNIC map[string]bool
	var observedDisk []string
	nicStateProbe = func(ctx context.Context) ([]uint64, error) {
		observedNIC, _ = ctx.Value(nic.NICKey).(map[string]bool)
		return []uint64{0, 0}, nil
	}
	diskStateProbe = func(ctx context.Context) (uint64, error) {
		observedDisk, _ = ctx.Value(disk.DiskKey).([]string)
		return 0, nil
	}
	t.Cleanup(func() {
		nicStateProbe = originalNICProbe
		diskStateProbe = originalDiskStateProbe
	})

	// When
	TrackNetworkSpeed(nil)
	getDiskUsed(nil)

	// Then
	if observedNIC != nil || observedDisk != nil {
		t.Fatalf("nil snapshot views = NIC:%v disk:%v, want nil empty views", observedNIC, observedDisk)
	}
}

func TestFetchIPUsesDefaultEndpointsWhenSnapshotEndpointsAreEmpty(t *testing.T) {
	// Given
	originalFetchIPProbe := fetchIPProbe
	var observed [][]string
	var observedLock sync.Mutex
	fetchIPProbe = func(endpoints []string, isV6 bool) string {
		observedLock.Lock()
		defer observedLock.Unlock()
		observed = append(observed, endpoints)
		if isV6 {
			return "2001:db8::4"
		}
		return "192.0.2.4"
	}
	t.Cleanup(func() { fetchIPProbe = originalFetchIPProbe })

	// When
	FetchIP(&model.AgentConfig{}, false)

	// Then
	if len(observed) != 2 {
		t.Fatalf("IP probe calls = %d, want IPv4 and IPv6", len(observed))
	}
	for _, endpoints := range observed {
		if !slices.Equal(endpoints, cfList) {
			t.Fatalf("empty snapshot endpoints selected %v, want defaults %v", endpoints, cfList)
		}
	}
}
