//go:build windows

package processgroup

import (
	"os"
	"testing"
)

// Windows counterpart of the unix pgid-fallback safety test: AddProcess must
// refuse a closed group and register nothing, so a caller cannot leak an
// OpenProcess handle into / assign a process onto a job whose handle has
// already been released. The spawned helper here is deliberately NOT added to
// the group and is killed directly.
func TestProcessExitGroup_AddProcessAfterCloseRegistersNothing(t *testing.T) {
	cmd := NewSuspendedExecCommand(os.Args[0], "-test.run=^TestHelperDescendantProcess$")
	cmd.Env = append(os.Environ(), "PROCESSGROUP_TEST_DESC=1", envDescToken+"=addproc-win")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	pg.Close()

	if err := pg.AddProcess(cmd); err != errProcessExitGroupClosed {
		t.Fatalf("AddProcess on closed group must return errProcessExitGroupClosed, got %v", err)
	}
	if len(pg.cmds) != 0 || len(pg.procs) != 0 {
		t.Fatalf("closed group must register nothing, got cmds=%d procs=%d", len(pg.cmds), len(pg.procs))
	}
}
