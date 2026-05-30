//go:build unix && !aix

package main

import (
	"os/exec"
	"syscall"
)

// killProcessGroupHard SIGKILLs the whole group via a pgid captured at
// Start time; looking it up via Getpgid(leader.Pid) at kill time races
// cmd.Wait reaping the leader and would leak still-running descendants.
//
// LIMITATION: this only reaches processes still in the leader's process
// group. A child that calls setsid()/setpgid() (e.g. `setsid daemon &`)
// detaches into a new session/group and survives this kill, becoming an
// orphan reparented to init. Fully containing such escapes needs cgroup
// v2 / PID-namespace confinement, which the agent does not currently set
// up. Exec timeout therefore guarantees the foreground tree is killed,
// not that every deliberately-daemonized descendant is.
func killProcessGroupHard(cmd *exec.Cmd, pgid int) {
	if pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
