//go:build !windows

package pty

import (
	"os/exec"
	"syscall"
	"testing"
)

// Regression for the Kill(-0) footgun: when Getpgid fails, resolveGroupKillPgid
// MUST return 0 so killChildProcess falls back to a single-process kill instead
// of syscall.Kill(-0, SIGKILL), which would signal the agent's own process
// group and take the whole agent down. Same class of bug as processgroup
// fix #123.
func TestResolveGroupKillPgid_GetpgidFailureReturnsZero(t *testing.T) {
	const sentinelPid = -424242
	if _, err := syscall.Getpgid(sentinelPid); err == nil {
		t.Skipf("Getpgid(%d) unexpectedly succeeded; pick another sentinel", sentinelPid)
	}
	if pgid := resolveGroupKillPgid(sentinelPid); pgid != 0 {
		t.Fatalf("Getpgid failure must yield pgid=0 (single-process kill), got %d", pgid)
	}
}

// A real backgrounded child created with Setpgid:true must resolve to its own
// positive pgid so the group kill path is taken — proving the success branch
// still does a real group kill rather than degrading to single-process.
func TestResolveGroupKillPgid_ValidProcessReturnsOwnGroup(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pgid := resolveGroupKillPgid(cmd.Process.Pid)
	if pgid <= 0 {
		t.Fatalf("valid Setpgid child must resolve to a positive pgid, got %d", pgid)
	}
	want, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("Getpgid: %v", err)
	}
	if pgid != want {
		t.Fatalf("resolved pgid %d must equal Getpgid %d", pgid, want)
	}
	// The child set its own group (Setpgid), so its pgid must NOT be the test
	// runner's own group — otherwise a group kill would hit us.
	if pgid == syscall.Getpgrp() {
		t.Fatalf("child pgid must differ from the test runner's group %d", pgid)
	}
}
