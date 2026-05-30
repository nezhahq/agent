package main

import (
	"os/exec"
	"runtime"
	"testing"

	"github.com/nezhahq/agent/pkg/processgroup"
)

// When cmd.Start() succeeds but a later setup step (AddProcess /
// ResumeMainThread) fails, the error path must both kill AND reap the started
// process. Killing without cmd.Wait() leaks the os.Process handle (Windows
// process handle / Unix zombie) on every such failure. killAndReapAfterStart
// guarantees the started process is waited on so its OS resources are
// released.
func TestKillAndReapAfterStart_ReleasesProcess(t *testing.T) {
	// Use the production constructor so the child gets its OWN process group
	// (Setpgid on unix). A plain exec.Command would inherit the test runner's
	// group and killProcessGroupHard(-pgid) would kill the test process.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = processgroup.NewSuspendedExecCommand("cmd", "/c", "ping -n 30 127.0.0.1 >NUL")
	} else {
		cmd = processgroup.NewSuspendedExecCommand("sleep", "30")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start helper process: %v", err)
	}
	pgid := processGroupID(cmd)

	killAndReapAfterStart(cmd, pgid)

	if cmd.ProcessState == nil {
		t.Fatal("killAndReapAfterStart must cmd.Wait() the started process so its OS handle is released; ProcessState is still nil")
	}
}

// Sanity: the helper must not panic on a nil command.
func TestKillAndReapAfterStart_NilSafe(t *testing.T) {
	killAndReapAfterStart(nil, 0)
}
