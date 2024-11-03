package load

import (
	"context"

	psLoad "github.com/shirou/gopsutil/v4/load"
)

func GetState(ctx context.Context) (*psLoad.AvgStat, error) {
	return psLoad.AvgWithContext(ctx)
}
