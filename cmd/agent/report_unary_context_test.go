package main

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
)

type reportUnaryContextClient struct {
	pb.NezhaServiceClient
	hostStarted  chan context.Context
	geoIPStarted chan context.Context
}

func (c *reportUnaryContextClient) ReportSystemInfo2(ctx context.Context, _ *pb.Host, _ ...grpc.CallOption) (*pb.Uint64Receipt, error) {
	c.hostStarted <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

func (c *reportUnaryContextClient) ReportGeoIP(ctx context.Context, _ *pb.GeoIP, _ ...grpc.CallOption) (*pb.GeoIP, error) {
	c.geoIPStarted <- ctx
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestReportHostDeadline_ParentCancellationReachesUnderlyingRPC(t *testing.T) {
	// Given
	restore := installReportUnaryContextFixture(t)
	defer restore()
	parent, cancelParent := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- reportHost(parent, &model.AgentConfig{}) }()
	rpcContext := awaitStreamOperationResult(t, client.(*reportUnaryContextClient).hostStarted)
	assertTenSecondReportDeadline(t, rpcContext)

	// When
	cancelParent()
	reported := awaitStreamOperationResult(t, result)

	// Then
	if reported {
		t.Fatal("reportHost returned success after parent cancellation")
	}
	if !errors.Is(rpcContext.Err(), context.Canceled) {
		t.Fatalf("ReportSystemInfo2 context error = %v, want context.Canceled", rpcContext.Err())
	}
}

func TestReportGeoIPDeadline_ParentCancellationReachesUnderlyingRPC(t *testing.T) {
	// Given
	restore := installReportUnaryContextFixture(t)
	defer restore()
	parent, cancelParent := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() {
		result <- reportGeoIP(parent, &model.AgentConfig{}, geoIPReportOptions{forceUpdate: true})
	}()
	rpcContext := awaitStreamOperationResult(t, client.(*reportUnaryContextClient).geoIPStarted)
	assertTenSecondReportDeadline(t, rpcContext)

	// When
	cancelParent()
	reported := awaitStreamOperationResult(t, result)

	// Then
	if reported {
		t.Fatal("reportGeoIP returned success after parent cancellation")
	}
	if !errors.Is(rpcContext.Err(), context.Canceled) {
		t.Fatalf("ReportGeoIP context error = %v, want context.Canceled", rpcContext.Err())
	}
}

func TestReportHostDeadline_ExpiresUnderlyingRPC(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given
		restore := installReportUnaryContextFixture(t)
		defer restore()
		result := make(chan bool, 1)
		go func() { result <- reportHost(context.Background(), &model.AgentConfig{}) }()
		rpcContext := <-client.(*reportUnaryContextClient).hostStarted

		// When
		time.Sleep(10 * time.Second)
		synctest.Wait()
		reported := <-result

		// Then
		if reported {
			t.Fatal("reportHost returned success after its RPC deadline")
		}
		if !errors.Is(rpcContext.Err(), context.DeadlineExceeded) {
			t.Fatalf("ReportSystemInfo2 context error = %v, want context.DeadlineExceeded", rpcContext.Err())
		}
	})
}

func TestReportGeoIPDeadline_ExpiresUnderlyingRPC(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given
		restore := installReportUnaryContextFixture(t)
		defer restore()
		result := make(chan bool, 1)
		go func() {
			result <- reportGeoIP(context.Background(), &model.AgentConfig{}, geoIPReportOptions{forceUpdate: true})
		}()
		rpcContext := <-client.(*reportUnaryContextClient).geoIPStarted

		// When
		time.Sleep(10 * time.Second)
		synctest.Wait()
		reported := <-result

		// Then
		if reported {
			t.Fatal("reportGeoIP returned success after its RPC deadline")
		}
		if !errors.Is(rpcContext.Err(), context.DeadlineExceeded) {
			t.Fatalf("ReportGeoIP context error = %v, want context.DeadlineExceeded", rpcContext.Err())
		}
	})
}

func installReportUnaryContextFixture(t *testing.T) func() {
	t.Helper()
	originalClient := client
	originalInitialized := initialized
	originalDependencies := reportMonitorDependencies
	originalHostStatus := hostStatus.Load()
	originalIPStatus := ipStatus.Load()
	client = &reportUnaryContextClient{
		hostStarted:  make(chan context.Context, 1),
		geoIPStarted: make(chan context.Context, 1),
	}
	initialized = true
	hostStatus.Store(false)
	ipStatus.Store(false)
	reportMonitorDependencies.getHost = func(*model.AgentConfig) *model.Host { return &model.Host{} }
	reportMonitorDependencies.fetchIP = func(*model.AgentConfig, bool) *pb.GeoIP {
		return &pb.GeoIP{Ip: &pb.IP{Ipv4: "192.0.2.20"}}
	}
	reportMonitorDependencies.geoIPChanged = func() bool { return true }
	return func() {
		client = originalClient
		initialized = originalInitialized
		reportMonitorDependencies = originalDependencies
		hostStatus.Store(originalHostStatus)
		ipStatus.Store(originalIPStatus)
	}
}

func assertTenSecondReportDeadline(t *testing.T, ctx context.Context) {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("report RPC context has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 9*time.Second || remaining > 10*time.Second {
		t.Fatalf("report RPC deadline remaining = %v, want (9s, 10s]", remaining)
	}
}
