//go:build linux || darwin

package main

import (
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// H11 regression: a child that detaches into its own session (setsid) while
// holding stdout open MUST NOT block handleExecTask past the timeout. Before
// the pipe-based stdio refactor, cmd.Wait sat on the inherited stdout copy
// goroutine forever and the timeout branch was effectively a no-op.
//
// The test launches a shell that spawns a detached grandchild keeping stdout
// open for 30s, requests a 1s timeout, and asserts handleExecTask returns
// well before the grandchild would naturally exit.
func TestHandleExecTask_TimeoutTerminatesEvenWhenDaemonizedChildHoldsStdout(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("daemonized-child stdout-holder reproducer is POSIX-only")
	}

	req := model.ExecRequest{
		Cmd: "sh",
		Args: []string{"-c",
			"setsid sh -c 'sleep 30 >&1' & sleep 30",
		},
		TimeoutSeconds: 1,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	task := &pb.Task{Data: string(body)}
	result := &pb.TaskResult{}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		handleExecTask(task, result)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatalf("handleExecTask did not return within 8s — daemonized stdout holder pinned cmd.Wait (elapsed=%s)", time.Since(start))
	}

	elapsed := time.Since(start)
	if elapsed > 6*time.Second {
		t.Fatalf("handleExecTask returned but took %s — pipe close on timeout regressed", elapsed)
	}

	var res model.ExecResult
	if err := json.Unmarshal([]byte(result.GetData()), &res); err != nil {
		t.Fatalf("invalid result payload: %v", err)
	}
	if !res.TimedOut {
		t.Fatal("TimedOut flag must be set when the deadline fires")
	}
}
