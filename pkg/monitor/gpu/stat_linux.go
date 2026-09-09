//go:build linux

package gpu

import (
	"context"

	"github.com/nezhahq/agent/pkg/monitor/gpu/vendor"
)

// detailedStat covers NVIDIA, whose nvidia-smi output already carries frame
// buffer figures. Other vendors report the generic path.
func detailedStat(_ context.Context) ([]vendor.GPUStat, bool, error) {
	if vendorType != vendorNVIDIA {
		return nil, false, nil
	}
	smi := &vendor.NvidiaSMI{BinPath: "/usr/bin/nvidia-smi"}
	if err := smi.Start(); err != nil {
		return nil, true, err
	}
	stats, err := smi.GatherStat()
	return stats, true, err
}
