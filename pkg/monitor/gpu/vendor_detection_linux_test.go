//go:build linux

package gpu

import (
	"context"
	"sync"
	"testing"
)

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
	if detectedVendor != 0 {
		t.Fatalf("vendor %d was detected before any GPU query", detectedVendor)
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
