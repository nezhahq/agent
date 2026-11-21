package vendor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func hangingTool(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script as the stand-in tool")
	}
	path := filepath.Join(t.TempDir(), "hanging-gpu-tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// GPU statistics are collected while the monitor's state lock is held. A
// vendor tool that hangs (a wedged driver is enough) therefore stopped every
// state report of the agent, not just the GPU figures.
func TestNvidiaSMI_HangingToolIsAbandonedAfterTimeout(t *testing.T) {
	originalTimeout := gpuToolTimeout
	t.Cleanup(func() { gpuToolTimeout = originalTimeout })
	gpuToolTimeout = 300 * time.Millisecond
	smi := &NvidiaSMI{BinPath: hangingTool(t)}

	started := time.Now()
	output := smi.pollNvidiaSMI()

	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("poll returned after %s, want it bounded by the timeout", elapsed)
	}
	if output != nil {
		t.Fatalf("poll returned output %q for a tool that never finished", output)
	}
}

// intel_gpu_top prints nothing when the driver is wedged. Without a timeout the
// collection never returned, and with it every state report of the agent.
func TestIntelGPUTop_HangingToolIsAbandonedAfterTimeout(t *testing.T) {
	originalTimeout := gpuToolTimeout
	t.Cleanup(func() { gpuToolTimeout = originalTimeout })
	gpuToolTimeout = 300 * time.Millisecond
	igt := &IntelGPUTop{BinPath: hangingTool(t)}

	started := time.Now()
	_, err := igt.collectStats()

	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("collection returned after %s, want it bounded by the timeout", elapsed)
	}
	if err == nil {
		t.Fatal("collection reported success for a tool that printed nothing")
	}
}
