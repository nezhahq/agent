//go:build unix && !aix

package processgroup

import (
	"context"
	"os/exec"
	"testing"
)

// Every command constructor MUST set Setpgid:true. The whole unix kill path in
// Dispose/ReapDescendants relies on syscall.Kill(-pgid, SIGKILL); a constructor
// that forgets Setpgid silently degrades the group kill to a single-process
// kill and lets descendants leak. This locks the pgid contract for all four
// entry points used by the MCP exec path.
func TestCommandConstructors_SetUnixProcessGroup(t *testing.T) {
	cases := map[string]*exec.Cmd{
		"NewCommand":              NewCommand("echo hi"),
		"NewExecCommand":          NewExecCommand("echo", "hi"),
		"NewExecCommandContext":   NewExecCommandContext(context.Background(), "echo", "hi"),
		"NewSuspendedExecCommand": NewSuspendedExecCommand("echo", "hi"),
	}

	for name, cmd := range cases {
		if cmd == nil {
			t.Fatalf("%s returned nil cmd", name)
		}
		if cmd.SysProcAttr == nil {
			t.Fatalf("%s must set SysProcAttr to carry Setpgid", name)
		}
		if !cmd.SysProcAttr.Setpgid {
			t.Fatalf("%s must set Setpgid=true so the pgid kill path can reap descendants", name)
		}
	}
}
