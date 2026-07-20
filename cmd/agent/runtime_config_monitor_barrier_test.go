package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
)

func TestRuntimeConfigMonitorUsesOneCallerSnapshotAfterBPublishes(t *testing.T) {
	// Given
	a := model.AgentConfig{
		Server:                      "generation-a",
		GPU:                         true,
		Temperature:                 true,
		NICAllowlist:                map[string]bool{"nic-a": true},
		HardDrivePartitionAllowlist: []string{"/disk-a"},
		CustomIPApi:                 []string{"https://ip-a.example.test"},
		IPReportPeriod:              60,
	}
	b := model.AgentConfig{
		Server:                      "generation-b",
		NICAllowlist:                map[string]bool{"nic-b": true},
		HardDrivePartitionAllowlist: []string{"/disk-b"},
		CustomIPApi:                 []string{"https://ip-b.example.test"},
		UseIPv6CountryCode:          true,
	}
	snapshotA := publishRuntimeConfig(a)
	observation := installReportMonitorSnapshotBarrier(t, snapshotA, b)
	originalClient, originalInitialized := client, initialized
	originalGeoIPReported := geoipReported
	originalDashboardBootTime := prevDashboardBootTime
	client = &snapshotReportClient{}
	initialized = true
	geoipReported = false
	t.Cleanup(func() {
		client = originalClient
		initialized = originalInitialized
		geoipReported = originalGeoIPReported
		prevDashboardBootTime = originalDashboardBootTime
	})
	stream := &snapshotReportStateStream{ctx: context.Background()}
	schedule := reportSchedule{host: time.Time{}, ip: time.Time{}}
	reportConfig := reportConfigTupleFrom(snapshotA)

	// When
	_, err := reportState(stream, schedule, reportConfig)

	// Then
	if err != nil {
		t.Fatalf("reportState: %v", err)
	}
	if err := observation.validate(snapshotA); err != nil {
		t.Fatal(err)
	}
	t.Logf("generation A pointer=%p server=%q reached track/state/host/fetch after generation B publication", snapshotA, snapshotA.Server)
}

func TestReportMonitorObservationRejectsPointersWithoutDependencyCalls(t *testing.T) {
	// Given
	snapshot := &model.AgentConfig{
		Server:                      "generation-a",
		NICAllowlist:                map[string]bool{"nic-a": true},
		HardDrivePartitionAllowlist: []string{"/disk-a"},
		CustomIPApi:                 []string{"https://ip-a.example.test"},
	}
	observation := &reportMonitorSnapshotObservation{
		configs: map[string]*model.AgentConfig{
			"track": snapshot,
			"state": snapshot,
			"host":  snapshot,
			"fetch": snapshot,
		},
		calls: make(map[string]int),
	}

	// When
	err := observation.validate(snapshot)

	// Then
	if err == nil {
		t.Fatal("stored pointers without dependency calls must fail observation validation")
	}
}

type reportMonitorSnapshotObservation struct {
	mu       sync.Mutex
	configs  map[string]*model.AgentConfig
	calls    map[string]int
	barriers int
}

func installReportMonitorSnapshotBarrier(t *testing.T, snapshotA *model.AgentConfig, b model.AgentConfig) *reportMonitorSnapshotObservation {
	t.Helper()
	originalDependencies := reportMonitorDependencies
	originalSnapshot := runtimeConfigSnapshot.Load()
	observation := &reportMonitorSnapshotObservation{
		configs: make(map[string]*model.AgentConfig),
		calls:   make(map[string]int),
	}
	record := func(name string, config *model.AgentConfig) {
		observation.mu.Lock()
		observation.configs[name] = config
		observation.calls[name]++
		observation.mu.Unlock()
	}
	reportMonitorDependencies = reportMonitorDependencySet{
		trackNetworkSpeed: func(config *model.AgentConfig) {
			record("track", config)
			observation.mu.Lock()
			observation.barriers++
			observation.mu.Unlock()
			publishRuntimeConfig(b)
		},
		getState: func(config *model.AgentConfig, _, _ bool) *model.HostState {
			record("state", config)
			return &model.HostState{}
		},
		getHost: func(config *model.AgentConfig) *model.Host {
			record("host", config)
			return &model.Host{}
		},
		fetchIP: func(config *model.AgentConfig, _ bool) *pb.GeoIP {
			record("fetch", config)
			return &pb.GeoIP{Ip: &pb.IP{Ipv4: "192.0.2.10"}}
		},
		geoIPChanged: func() bool { return true },
		markGeoIPReported: func(string) {
			observation.mu.Lock()
			observation.calls["mark_geo_ip_reported"]++
			observation.mu.Unlock()
		},
	}
	t.Cleanup(func() {
		reportMonitorDependencies = originalDependencies
		runtimeConfigSnapshot.Store(originalSnapshot)
		if observation.barriers != 1 {
			t.Errorf("report monitor publication barriers = %d, want exactly 1", observation.barriers)
		}
	})
	return observation
}

func (o *reportMonitorSnapshotObservation) validate(snapshotA *model.AgentConfig) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, dependency := range []string{"track", "state", "host", "fetch"} {
		if o.calls[dependency] != 1 {
			return fmt.Errorf("%s calls = %d, want exactly 1", dependency, o.calls[dependency])
		}
		observed := o.configs[dependency]
		if observed != snapshotA {
			return fmt.Errorf("%s config pointer = %p (%+v), want generation A pointer %p", dependency, observed, observed, snapshotA)
		}
		if observed.Server != "generation-a" || !observed.NICAllowlist["nic-a"] || observed.HardDrivePartitionAllowlist[0] != "/disk-a" || observed.CustomIPApi[0] != "https://ip-a.example.test" {
			return fmt.Errorf("%s observed mixed or aliased generation: %+v", dependency, observed)
		}
	}
	if o.calls["mark_geo_ip_reported"] != 1 {
		return fmt.Errorf("mark GeoIP reported calls = %d, want exactly 1", o.calls["mark_geo_ip_reported"])
	}
	return nil
}

type snapshotReportStateStream struct {
	pb.NezhaService_ReportSystemStateClient
	ctx context.Context
}

func (s *snapshotReportStateStream) Context() context.Context { return s.ctx }
func (s *snapshotReportStateStream) Send(*pb.State) error     { return nil }
func (s *snapshotReportStateStream) Recv() (*pb.Receipt, error) {
	return &pb.Receipt{}, nil
}

type snapshotReportClient struct {
	pb.NezhaServiceClient
}

func (c *snapshotReportClient) ReportSystemInfo2(context.Context, *pb.Host, ...grpc.CallOption) (*pb.Uint64Receipt, error) {
	return &pb.Uint64Receipt{}, nil
}

func (c *snapshotReportClient) ReportGeoIP(context.Context, *pb.GeoIP, ...grpc.CallOption) (*pb.GeoIP, error) {
	return &pb.GeoIP{CountryCode: "test"}, nil
}
