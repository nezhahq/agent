package main

import (
	"testing"
	"time"
)

func TestIntegratedReloadFixtureDoesNotDisturbPreexistingTimer(t *testing.T) {
	restoreIntegratedRaceGlobals(t)
	reloadMu.Lock()
	originalTimer := reloadTimer
	originalTransfer := reloadIsTransfer
	reloadMu.Unlock()
	fired := make(chan struct{}, 1)
	externalTimer := time.AfterFunc(50*time.Millisecond, func() { fired <- struct{}{} })
	t.Cleanup(func() {
		externalTimer.Stop()
		reloadMu.Lock()
		reloadTimer = originalTimer
		reloadIsTransfer = originalTransfer
		reloadMu.Unlock()
	})
	reloadMu.Lock()
	reloadTimer = externalTimer
	reloadIsTransfer = true
	reloadMu.Unlock()

	commitIntegratedReload(t, integratedGenerationConfig(integratedGenerationA), integratedGenerationConfig(integratedGenerationB))
	reloadMu.Lock()
	retainedTimer := reloadTimer
	retainedTransfer := reloadIsTransfer
	reloadMu.Unlock()
	if retainedTimer != externalTimer || !retainedTransfer {
		t.Fatalf("integrated fixture changed preexisting reload state: timerSame=%t isTransfer=%t", retainedTimer == externalTimer, retainedTransfer)
	}

	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	select {
	case <-fired:
	case <-deadline.C:
		t.Fatal("preexisting external timer did not fire after integrated reload fixture")
	}
}
