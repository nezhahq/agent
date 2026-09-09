package gpu

import (
	"context"

	"github.com/nezhahq/agent/pkg/monitor/gpu/vendor"
)

// GetStat reports per-card utilization plus memory where the vendor exposes
// it. Vendors and platforms without memory reporting fall back to
// utilization-only, leaving the memory fields zero.
func GetStat(ctx context.Context) ([]vendor.GPUStat, error) {
	if stats, ok, err := detailedStat(ctx); ok {
		return stats, err
	}

	util, err := GetState(ctx)
	if err != nil {
		return nil, err
	}
	stats := make([]vendor.GPUStat, len(util))
	for i, u := range util {
		stats[i] = vendor.GPUStat{Utilization: u}
	}
	return stats, nil
}
