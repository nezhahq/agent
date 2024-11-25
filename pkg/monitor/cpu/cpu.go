package cpu

import (
	"context"
	"fmt"

	psCpu "github.com/shirou/gopsutil/v4/cpu"
)

type CPUHostType string

const CPUHostKey CPUHostType = "cpu"

func GetHost(ctx context.Context) ([]string, error) {
	ci, err := psCpu.InfoWithContext(ctx)
	if err != nil {
		return nil, err
	}

	cpuModelCount := make(map[string]int)
	for _, c := range ci {
		cpuModelCount[c.ModelName] += int(c.Cores)
	}

	var cpuType string
	if t, ok := ctx.Value(CPUHostKey).(string); ok {
		cpuType = t
	}

	ch := make([]string, 0, len(cpuModelCount))
	for model, count := range cpuModelCount {
		ch = append(ch, fmt.Sprintf("%s %d %s Core", model, count, cpuType))
	}

	return ch, nil
}

func GetState(ctx context.Context) ([]float64, error) {
	cp, err := psCpu.PercentWithContext(ctx, 0, false)
	if err != nil {
		return nil, err
	}

	return cp, nil
}
