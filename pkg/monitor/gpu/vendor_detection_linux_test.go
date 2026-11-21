//go:build linux

package gpu

import (
	"context"
	"os"
	"sync"
	"testing"
)

// vendorProbeRunsAtPackageLoad is read in TestMain, after every package
// initialiser has run and before any test queries the GPU.
var vendorProbeRunsAtPackageLoad int32

func TestMain(m *testing.M) {
	vendorProbeRunsAtPackageLoad = vendorProbeRuns.Load()
	os.Exit(m.Run())
}

// Detecting the GPU vendor runs vendor tools that can hang on a broken driver.
// It used to run while the package was initialised, delaying every start of
// the agent, GPU monitoring enabled or not. It must wait for the first query
// and run once.
func TestVendorDetectionWaitsForTheFirstQueryAndRunsOnce(t *testing.T) {
	originalProbe := probeVendor
	t.Cleanup(func() {
		probeVendor = originalProbe
		detectVendorOnce = sync.Once{}
		detectedVendor = 0
	})
	if vendorProbeRunsAtPackageLoad != 0 {
		t.Fatalf("vendor detection ran %d time(s) while the package was loading", vendorProbeRunsAtPackageLoad)
	}
	probes := 0
	probeVendor = func() uint8 {
		probes++
		return 0
	}
	detectVendorOnce = sync.Once{}

	if probes != 0 {
		t.Fatal("replacing the probe ran it")
	}
	for query := 0; query < 3; query++ {
		if _, err := GetHost(context.Background()); err != nil {
			t.Fatalf("GetHost: %v", err)
		}
		if _, err := GetState(context.Background()); err != nil {
			t.Fatalf("GetState: %v", err)
		}
	}
	if probes != 1 {
		t.Fatalf("vendor detection ran %d times across six queries, want 1", probes)
	}
}
