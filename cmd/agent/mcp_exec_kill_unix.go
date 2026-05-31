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
// ACCEPTED LIMITATION (by design): this only reaches processes still in the
// leader's process group. A child that calls setsid()/setpgid() (e.g.
// `setsid daemon &`) detaches into a new session/group and survives this
// kill, becoming an orphan reparented to init. Fully containing such escapes
// needs cgroup v2 / PID-namespace confinement, which the agent intentionally
// does not set up (it would require cgroup delegation / privileged setup that
// is out of scope for a monitoring agent). This is acceptable under the
// threat model: MCP exec is a full-host capability gated by dashboard-side
// PAT scope + server whitelist + kill switch, so a caller able to run exec at
// all could already daemonize by intent. The timeout guarantee is therefore
// scoped to the foreground process group, NOT to deliberately-daemonized
// descendants. See TestExec_TimeoutKillsBackgroundDescendant for the
// same-process-group containment contract that IS upheld.
func killProcessGroupHard(cmd *exec.Cmd, pgid int) {
	if pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
