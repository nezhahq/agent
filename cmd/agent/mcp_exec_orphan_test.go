//go:build unix && !aix

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// Parent sh detaches a same-process-group grandchild (no setsid). Parent
// exits immediately, so handler returns via cmd.Wait — NOT the timeout
// branch. Cleanup must still kill the group; if it falls back to a
// leader-only kill, the grandchild lives and creates the sentinel.
func TestExec_TimeoutKillsBackgroundDescendant(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only process-group semantics")
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "grandchild-alive")

	script := "(sleep 3 && touch " + sentinel + ") >/dev/null 2>&1 </dev/null &"
	req := model.ExecRequest{
		Cmd:            "sh",
		Args:           []string{"-c", script},
		TimeoutSeconds: 5,
	}
	body, _ := json.Marshal(req)
	task := &pb.Task{Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult

	start := time.Now()
	handleExecTask(task, &res)
	elapsed := time.Since(start)

	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if elapsed > 2*time.Second {
		t.Fatalf("handler should return promptly after parent exits; took %s, result=%+v", elapsed, out)
	}

	time.Sleep(4 * time.Second)
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("grandchild survived: process group was not killed on exec cleanup")
	}
}
