package monitor

import (
	"context"
	"errors"
	"testing"

	psLoad "github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// A failing load probe yields a nil *AvgStat. GetState runs on the state
// reporting goroutine, so dereferencing it takes the whole agent down.
func TestGetStateSurvivesLoadProbeFailure(t *testing.T) {
	originalState := captureMonitorTestState()
	t.Cleanup(originalState.restore)

	virtualMemoryProbe = func() (*mem.VirtualMemoryStat, error) { return &mem.VirtualMemoryStat{}, nil }
	cpuStateProbe = func(context.Context) ([]float64, error) { return []float64{42}, nil }
	loadStateProbe = func(context.Context) (*psLoad.AvgStat, error) {
		return nil, errors.New("load average unavailable")
	}

	state := GetState(nil, true, true)

	if state == nil {
		t.Fatal("GetState returned nil")
	}
	if state.CPU != 42 {
		t.Fatalf("CPU = %v, want the value from the healthy probe", state.CPU)
	}
	if state.Load1 != 0 || state.Load5 != 0 || state.Load15 != 0 {
		t.Fatalf("load = %v/%v/%v, want zero values when the probe fails", state.Load1, state.Load5, state.Load15)
	}
}
