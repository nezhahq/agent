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

// Containment contract that IS upheld: when the timeout branch fires while
// the leader is still alive, a same-process-group background child must be
// SIGKILLed via the captured pgid. This pins killProcessGroupHard's
// guarantee for the foreground process group (the escape carve-out for
// setsid()/setpgid() is documented as an accepted limitation in
// mcp_exec_kill_unix.go and is intentionally NOT asserted here).
func TestExec_TimeoutBranchKillsSamePgidBackgroundChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only process-group semantics")
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "child-alive")

	// Background child sleeps then touches the sentinel, but the leader
	// blocks on `wait` so the handler exits via the TIMEOUT branch (not
	// cmd.Wait). The child stays in the leader's process group (no setsid),
	// so Dispose's group SIGKILL must reach it before it writes the file.
	script := "(sleep 3 && touch " + sentinel + ") & wait"
	req := model.ExecRequest{
		Cmd:            "sh",
		Args:           []string{"-c", script},
		TimeoutSeconds: 1,
	}
	body, _ := json.Marshal(req)
	task := &pb.Task{Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult

	handleExecTask(task, &res)

	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if !out.TimedOut {
		t.Fatalf("expected the timeout branch to fire, result=%+v", out)
	}

	time.Sleep(4 * time.Second)
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("same-pgid background child survived the timeout kill")
	}
}
