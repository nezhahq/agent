//go:build windows

package processgroup

import (
	"context"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// The three non-suspended constructors MUST set CREATE_NEW_PROCESS_GROUP so the
// JobObject + Ctrl signal handling has a distinct group to act on. This mirrors
// the unix Setpgid contract: a missing flag silently breaks descendant reaping.
func TestCommandConstructors_SetWindowsCreationFlags(t *testing.T) {
	cases := map[string]*exec.Cmd{
		"NewCommand":            NewCommand("echo hi"),
		"NewExecCommand":        NewExecCommand("cmd", "/c", "echo hi"),
		"NewExecCommandContext": NewExecCommandContext(context.Background(), "cmd", "/c", "echo hi"),
	}

	for name, cmd := range cases {
		if cmd == nil {
			t.Fatalf("%s returned nil cmd", name)
		}
		if cmd.SysProcAttr == nil {
			t.Fatalf("%s must set SysProcAttr to carry CreationFlags", name)
		}
		if cmd.SysProcAttr.CreationFlags&windows.CREATE_NEW_PROCESS_GROUP == 0 {
			t.Fatalf("%s must set CREATE_NEW_PROCESS_GROUP", name)
		}
	}
}

// The suspended constructor MUST add CREATE_SUSPENDED on top of
// CREATE_NEW_PROCESS_GROUP. CREATE_SUSPENDED is what lets the exec path attach
// the JobObject BEFORE any child code runs; dropping it reopens the
// fast-spawning-grandchild race that TerminateJobObject can't recover from.
func TestNewSuspendedExecCommand_SetsSuspendedAndProcessGroup(t *testing.T) {
	cmd := NewSuspendedExecCommand("cmd", "/c", "echo hi")
	if cmd == nil || cmd.SysProcAttr == nil {
		t.Fatal("NewSuspendedExecCommand must return a cmd with SysProcAttr set")
	}
	flags := cmd.SysProcAttr.CreationFlags
	if flags&windows.CREATE_NEW_PROCESS_GROUP == 0 {
		t.Fatal("suspended cmd must keep CREATE_NEW_PROCESS_GROUP")
	}
	if flags&windows.CREATE_SUSPENDED == 0 {
		t.Fatal("suspended cmd must set CREATE_SUSPENDED so the job is attached before the child runs")
	}
}
