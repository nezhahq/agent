package main

import (
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

// Race scenario: T1's AfterFunc callback gets queued to run after its 10s
// (or shorter) delay, but is preempted before it acquires reloadMu. T2 then
// arrives, acquires reloadMu, calls T1.Stop() (returns false: too late),
// installs its own timer as reloadTimer, releases the mutex. T1's stale
// callback resumes, acquires the mutex, and — if it only checks
// `reloadTimer == nil` — observes "non-nil" (it's T2's timer), happily
// commits T1's superseded config to disk and to agentConfig, and sets
// reloadTimer back to nil. T2's callback then fires, sees nil, exits — the
// agent silently locked itself out with the cancelled credential.
//
// The identity check (`reloadTimer != thisTimer`) closes the window. This
// test reproduces the race against the helper that performs the commit.
func TestApplyPendingReloadSkipsWhenSuperseded(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()

	agentConfig = model.AgentConfig{ClientSecret: "live"}

	// stale stands in for a timer whose AfterFunc body already started but
	// hadn't yet acquired reloadMu when supersede ran.
	stale := time.AfterFunc(time.Hour, func() {})
	defer stale.Stop()

	// active is the newer timer that supersede installed under the lock.
	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()

	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	applyPendingReload(stale, model.AgentConfig{ClientSecret: "superseded"})

	if agentConfig.ClientSecret != "live" {
		t.Fatalf("stale-timer callback must not clobber live agentConfig, got %q", agentConfig.ClientSecret)
	}
	reloadMu.Lock()
	stillActive := reloadTimer == active
	reloadMu.Unlock()
	if !stillActive {
		t.Fatal("the active reload timer must remain installed after a stale callback returns")
	}
}
