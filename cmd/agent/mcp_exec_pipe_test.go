//go:build linux || darwin

package main

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

// H11 regression: a child that detaches into its own session (setsid) while
// holding stdout open MUST NOT block handleExecTask past the timeout. Before
// the pipe-based stdio refactor, cmd.Wait sat on the inherited stdout copy
// goroutine forever and the timeout branch was effectively a no-op.
//
// The helper spawns a detached grandchild that writes through inherited stdout
// until the handler closes its reader, then the test verifies that PID exits.
func TestHandleExecTask_TimeoutTerminatesEvenWhenDaemonizedChildHoldsStdout(t *testing.T) {
	pidFile := t.TempDir() + "/timeout-retained-pipe.pid"
	done := make(chan model.ExecResult, 1)
	start := time.Now()
	go func() {
		done <- executeOutputHelper(execOutputHelperTimeout, pidFile, 1)
	}()

	var result model.ExecResult
	select {
	case result = <-done:
	case <-time.After(8 * time.Second):
		t.Fatalf("handleExecTask did not return within 8s — daemonized stdout holder pinned cmd.Wait (elapsed=%s)", time.Since(start))
	}

	elapsed := time.Since(start)
	if elapsed > 6*time.Second {
		t.Fatalf("handleExecTask returned but took %s — pipe close on timeout regressed", elapsed)
	}

	if !result.TimedOut {
		t.Fatal("TimedOut flag must be set when the deadline fires")
	}
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read daemonized descendant pid: %v", err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		t.Fatalf("parse daemonized descendant pid: %v", err)
	}
	awaitProcessExit(t, pid)
}
