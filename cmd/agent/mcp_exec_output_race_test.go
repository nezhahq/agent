//go:build linux || darwin

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// The stdout/stderr buffers are filled by background io.Copy goroutines.
// handleExecTask must not read outBuf/errBuf until those goroutines have
// finished, or the buffer read races their Write (bytes.Buffer is not
// concurrency-safe). The race window is the TIMEOUT branch: a detached
// grandchild keeps the stdout pipe open, so the copy goroutine is still
// blocked in Write/Read when the bounded "best-effort" drain gives up and
// the main goroutine reads the buffer. We reproduce exactly that — a
// daemonized child streaming output past a 1s deadline — and run under
// -race so the concurrent buffer access is flagged deterministically.
func TestHandleExecTask_TimeoutOutputReadIsRaceFree(t *testing.T) {
	req := model.ExecRequest{
		Cmd: "sh",
		Args: []string{"-c",
			"setsid sh -c 'while :; do echo spam; done >&1' & sleep 30",
		},
		TimeoutSeconds: 1,
		MaxOutputBytes: 1 << 20,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	task := &pb.Task{Data: string(body)}
	result := &pb.TaskResult{}

	handleExecTask(task, result)

	var res model.ExecResult
	if err := json.Unmarshal([]byte(result.GetData()), &res); err != nil {
		t.Fatalf("invalid result payload: %v", err)
	}
	if !res.TimedOut {
		t.Fatal("TimedOut flag must be set when the deadline fires")
	}
	_ = strings.Count(res.Stdout, "spam")
}
