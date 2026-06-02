//go:build unix && !aix

package processgroup

import (
	"os"
	"syscall"
	"testing"
)

// On the success path AddProcess must record a validated process-group id that
// matches the kernel's Getpgid for the spawned leader. This is the positive
// counterpart to TestAddProcess_GetpgidFailureDoesNotFallBackToPid: when
// Getpgid succeeds the stored pgid must be the real (>0) group so the later
// Kill(-pgid) hits the whole group rather than degrading to a single kill.
func TestProcessExitGroup_AddProcessRecordsValidatedProcessGroupID(t *testing.T) {
	cmd := NewExecCommand(os.Args[0], "-test.run=^TestHelperDescendantProcess$")
	cmd.Env = append(os.Environ(), "PROCESSGROUP_TEST_DESC=1", envDescToken+"=addproc-unix")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}

	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	t.Cleanup(func() {
		_ = pg.Dispose()
		_ = cmd.Wait()
	})

	if err := pg.AddProcess(cmd); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}

	if len(pg.cmds) != 1 || len(pg.pgids) != 1 {
		t.Fatalf("expected one cmd/pgid slot, got cmds=%d pgids=%d", len(pg.cmds), len(pg.pgids))
	}
	if pg.pgids[0] <= 0 {
		t.Fatalf("validated pgid must be > 0, got %d", pg.pgids[0])
	}
	want, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("Getpgid: %v", err)
	}
	if pg.pgids[0] != want {
		t.Fatalf("recorded pgid %d must equal Getpgid %d", pg.pgids[0], want)
	}
}
