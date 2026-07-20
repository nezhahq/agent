package monitor

import (
	"context"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor/nic"
	"github.com/nezhahq/agent/pkg/util"
)

var networkNow = time.Now

func TrackNetworkSpeed(config *model.AgentConfig) {
	var allowlist map[string]bool
	if config != nil {
		allowlist = config.NICAllowlist
	}
	ctx := context.WithValue(context.Background(), nic.NICKey, allowlist)
	networkState, err := nicStateProbe(ctx)
	if err != nil {
		return
	}

	innerNetInTransfer := networkState[0]
	innerNetOutTransfer := networkState[1]
	now := uint64(networkNow().Unix())
	metricLock.Lock()
	defer metricLock.Unlock()
	diff := util.SubUintChecked(now, lastUpdateNetStats)
	if diff > 0 {
		netInSpeed = util.SubUintChecked(innerNetInTransfer, netInTransfer) / diff
		netOutSpeed = util.SubUintChecked(innerNetOutTransfer, netOutTransfer) / diff
	}
	netInTransfer = innerNetInTransfer
	netOutTransfer = innerNetOutTransfer
	lastUpdateNetStats = now
}
