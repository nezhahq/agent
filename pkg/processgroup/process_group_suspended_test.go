package processgroup

import (
	"testing"
)

// H12 regression contract: ProcessExitGroup must expose a "start-suspended +
// add + resume" hook so the agent exec path can guarantee the JobObject is
// installed BEFORE the new process can spawn descendants. On Windows the
// stdlib's default flow is cmd.Start (process already running) →
// AssignProcessToJobObject, which leaves a race window where fast-spawning
// grandchildren escape the job. On POSIX the suspended path is a no-op and
// the function returns the cmd unchanged so callers stay portable.
func TestNewSuspendedExecCommand_ReturnsExecCmd(t *testing.T) {
	cmd := NewSuspendedExecCommand("sh", "-c", "echo hi")
	if cmd == nil {
		t.Fatal("NewSuspendedExecCommand must return a non-nil *exec.Cmd")
	}
	if cmd.Path == "" {
		t.Fatal("NewSuspendedExecCommand must return a callable *exec.Cmd with Path set")
	}
}

// ResumeMainThread MUST be a callable function on every platform. POSIX
// implements it as a no-op; Windows resumes the suspended primary thread
// after the job assignment so the process can finally execute.
func TestResumeMainThread_AvailableOnAllPlatforms(t *testing.T) {
	cmd := NewSuspendedExecCommand("sh", "-c", "true")
	if err := ResumeMainThread(cmd); err != nil {
		t.Fatalf("ResumeMainThread on a pre-Start cmd must succeed (no-op on POSIX), got %v", err)
	}
}
