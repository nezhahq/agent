//go:build !windows

package pty

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestPtyClose_TTYCloseErrorStillKillsAndWaitsForChild(t *testing.T) {
	// Given
	tty, err := os.CreateTemp(t.TempDir(), "closed-tty-")
	if err != nil {
		t.Fatalf("create tty fixture: %v", err)
	}
	if err := tty.Close(); err != nil {
		t.Fatalf("pre-close tty fixture: %v", err)
	}
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	terminal := &Pty{tty: tty, cmd: cmd}

	// When
	closeErr := terminal.Close()

	// Then
	if closeErr == nil {
		t.Fatal("Close must preserve the pre-closed tty error")
	}
	if cmd.ProcessState == nil {
		t.Fatal("Close must wait for the child even when tty.Close fails")
	}
	if !errors.Is(closeErr, os.ErrClosed) {
		t.Fatalf("Close error = %v, want closed-file error", closeErr)
	}
}
