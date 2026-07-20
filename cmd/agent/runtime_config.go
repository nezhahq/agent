package main

import (
	"sync/atomic"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/logger"
)

var (
	runtimeConfigSnapshot atomic.Pointer[model.AgentConfig]
	emptyRuntimeConfig    model.AgentConfig
)

func publishRuntimeConfig(cfg model.AgentConfig) *model.AgentConfig {
	snapshot := cfg.Clone()
	runtimeConfigSnapshot.Store(&snapshot)
	return &snapshot
}

func applyCommittedRuntimeConfig(cfg model.AgentConfig, notify func()) *model.AgentConfig {
	snapshot := publishRuntimeConfig(cfg)
	agentConfig = snapshot.Clone()
	geoipReported = false
	logger.SetEnable(snapshot.Debug)
	notify()
	return snapshot
}

// commitPendingRuntimeConfig keeps persistence ahead of every in-process
// publication while allowing callers to own timer metadata and notification.
func commitPendingRuntimeConfig(cfg model.AgentConfig, beforePublish, notify func()) error {
	if err := cfg.Save(); err != nil {
		return err
	}
	beforePublish()
	applyCommittedRuntimeConfig(cfg, notify)
	return nil
}

func notifyReloadWorker() {
	select {
	case reloadSigChan <- struct{}{}:
	default:
	}
}

func loadRuntimeConfig() *model.AgentConfig {
	if snapshot := runtimeConfigSnapshot.Load(); snapshot != nil {
		return snapshot
	}
	return &emptyRuntimeConfig
}
