//go:build !windows

package main

import (
	"runtime"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

// runCommandTask drives handleCommandTask the same way the task receive loop
// does and returns nothing — the test only cares about goroutine accounting.
func runCommandTask(cmd string) {
	handleCommandTask(&pb.Task{Data: cmd}, &pb.TaskResult{})
}

// settleGoroutines lets transient goroutines (os/exec reapers, GC) wind down so
// the count reflects only durable leaks, not in-flight teardown.
func settleGoroutines() int {
	var n int
	for i := 0; i < 50; i++ {
		runtime.GC()
		time.Sleep(20 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}

// TestHandleCommandTask_FailingCommandDoesNotLeakGoroutine is a regression test
// for the leak in handleCommandTask: when cmd.Wait() returns an error (any
// non-zero exit code), the function does not close endCh, so the timeout
// goroutine blocks on its select until the 2h timer fires. Each failing command
// strands one goroutine + one Timer. A monitoring deployment that runs probe
// commands returning non-zero accumulates goroutines until OOM.
//
// The test runs several failing commands and asserts the goroutine count does
// not grow. If the leak exists, the count climbs by ~the number of commands and
// this test fails (the intended red state).
func TestHandleCommandTask_FailingCommandDoesNotLeakGoroutine(t *testing.T) {
	if agentConfig.DisableCommandExecute {
		t.Skip("command execution disabled in this config")
	}

	// Warm up once so first-call lazy initialisation is not counted.
	runCommandTask("exit 1")

	base := settleGoroutines()

	const n = 20
	for i := 0; i < n; i++ {
		runCommandTask("exit 1")
	}

	after := settleGoroutines()

	if grew := after - base; grew > 2 {
		t.Fatalf("goroutine leak: ran %d failing commands, goroutines grew by %d (base=%d after=%d); "+
			"failing cmd.Wait() path never closes endCh, stranding the timeout goroutine",
			n, grew, base, after)
	}
}

// Control: a succeeding command (exit 0) takes the close(endCh) branch and must
// not leak, proving the harness itself is sound and isolating the failure path
// as the leak source.
func TestHandleCommandTask_SuccessfulCommandDoesNotLeakGoroutine(t *testing.T) {
	if agentConfig.DisableCommandExecute {
		t.Skip("command execution disabled in this config")
	}

	runCommandTask("true")

	base := settleGoroutines()

	const n = 20
	for i := 0; i < n; i++ {
		runCommandTask("true")
	}

	after := settleGoroutines()

	if grew := after - base; grew > 2 {
		t.Fatalf("goroutine leak on success path: ran %d commands, goroutines grew by %d (base=%d after=%d)",
			n, grew, base, after)
	}
}
