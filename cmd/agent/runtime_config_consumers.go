package main

import (
	"slices"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/util"
)

type dnsConfigTuple struct {
	configured bool
	servers    []string
}

type reportConfigTuple struct {
	snapshot            *model.AgentConfig
	reportDelay         uint32
	ipReportPeriod      uint32
	skipConnectionCount bool
	skipProcsCount      bool
	useIPv6CountryCode  bool
}

type reportSchedule struct {
	host time.Time
	ip   time.Time
}

type taskFeatureGates struct {
	disableForceUpdate    bool
	disableCommandExecute bool
	disableNat            bool
	disableSendQuery      bool
}

type updateConfigTuple struct {
	useAtomGitToUpgrade bool
	useGiteeToUpgrade   bool
}

type startupConfigView struct {
	debug             bool
	disableAutoUpdate bool
	selfUpdatePeriod  uint32
}

var runtimeConfigConsumerBarrier = func(string) {}

func dnsConfigTupleFrom(config *model.AgentConfig) dnsConfigTuple {
	configured := len(config.DNS) > 0
	runtimeConfigConsumerBarrier("dns")
	servers := util.DNSServersAll
	if configured {
		servers = config.DNS
	}
	return dnsConfigTuple{configured: configured, servers: slices.Clone(servers)}
}

func reportConfigTupleFrom(config *model.AgentConfig) reportConfigTuple {
	tuple := reportConfigTuple{
		snapshot:            config,
		reportDelay:         config.ReportDelay,
		skipConnectionCount: config.SkipConnectionCount,
		skipProcsCount:      config.SkipProcsCount,
	}
	runtimeConfigConsumerBarrier("report")
	tuple.ipReportPeriod = config.IPReportPeriod
	tuple.useIPv6CountryCode = config.UseIPv6CountryCode
	return tuple
}

func taskFeatureGatesFrom(config *model.AgentConfig) taskFeatureGates {
	gates := taskFeatureGates{
		disableCommandExecute: config.DisableCommandExecute,
		disableSendQuery:      config.DisableSendQuery,
	}
	runtimeConfigConsumerBarrier("task")
	gates.disableForceUpdate = config.DisableForceUpdate
	gates.disableNat = config.DisableNat
	return gates
}

func updateConfigTupleFrom(config *model.AgentConfig) updateConfigTuple {
	return updateConfigTuple{
		useAtomGitToUpgrade: config.UseAtomGitToUpgrade,
		useGiteeToUpgrade:   config.UseGiteeToUpgrade,
	}
}

func startupConfigViewFrom(config *model.AgentConfig) startupConfigView {
	return startupConfigView{
		debug:             config.Debug,
		disableAutoUpdate: config.DisableAutoUpdate,
		selfUpdatePeriod:  config.SelfUpdatePeriod,
	}
}
