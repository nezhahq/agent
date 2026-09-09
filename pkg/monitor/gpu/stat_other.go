//go:build !linux

package gpu

import (
	"context"

	"github.com/nezhahq/agent/pkg/monitor/gpu/vendor"
)

// detailedStat has no memory-capable path outside Linux yet; GetStat falls
// back to utilization-only.
func detailedStat(_ context.Context) ([]vendor.GPUStat, bool, error) {
	return nil, false, nil
}
