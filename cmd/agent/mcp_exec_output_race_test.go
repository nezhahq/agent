//go:build linux || darwin

package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// The stdout/stderr buffers are filled by background io.Copy goroutines.
// handleExecTask must not read outBuf/errBuf until those goroutines have
// finished, or the buffer read races their Write (bytes.Buffer is not
// concurrency-safe). The race window is the TIMEOUT branch: a detached
// grandchild keeps the stdout pipe open, so the copy goroutine is still
// blocked in Write/Read when the bounded "best-effort" drain gives up and
// the main goroutine reads the buffer. We reproduce exactly that — a
// daemonized child streaming output past a 1s deadline — and run under -race
// so concurrent buffer access is flagged while the helper PID proves cleanup.
func TestHandleExecTask_TimeoutOutputReadIsRaceFree(t *testing.T) {
	pidFile := t.TempDir() + "/race-retained-pipe.pid"
	result := executeOutputHelperWithMaxOutput(execOutputHelperTimeout, pidFile, 1, 1<<20)
	if !result.TimedOut {
		t.Fatal("TimedOut flag must be set when the deadline fires")
	}
	_ = strings.Count(result.Stdout, "retained-output")
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read race descendant pid: %v", err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		t.Fatalf("parse race descendant pid: %v", err)
	}
	awaitProcessExit(t, pid)
}
