package processgroup

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// startLeaderWithDescendant launches the test binary as a leader that spawns a
// long-lived descendant, both inheriting the returned stdout pipe. It uses the
// suspended-safe flow (suspended start -> AddProcess -> ResumeMainThread) so on
// Windows the JobObject is attached before the leader can spawn the descendant,
// and on unix the pgid is established pre-exec. It blocks until the descendant
// prints "READY <token>" so the caller knows the whole tree is live, then
// returns the group, the leader cmd, and the read end of the shared pipe.
func startLeaderWithDescendant(t *testing.T, mode, token string) (procExitGroupForTest, *exec.Cmd, *os.File) {
	t.Helper()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	cmd := NewSuspendedExecCommand(os.Args[0], "-test.run=^TestHelperLeaderProcess$")
	cmd.Env = append(os.Environ(), envLeaderMode+"="+mode, envDescToken+"="+token)
	cmd.Stdout = pw
	cmd.Stderr = os.Stderr

	pg := newProcExitGroupForTest(t)

	if err := cmd.Start(); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		t.Fatalf("leader Start: %v", err)
	}
	if err := pg.AddProcess(cmd); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		t.Fatalf("AddProcess: %v", err)
	}
	if err := ResumeMainThread(cmd); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		t.Fatalf("ResumeMainThread: %v", err)
	}

	// Close our copy of the write end so the only remaining writers are the
	// leader/descendant; otherwise the reader never sees EOF after they die.
	_ = pw.Close()

	waitForReady(t, pr, token)
	return pg, cmd, pr
}

// waitForReady blocks until the helper prints "READY <token>" on the pipe or
// the test deadline elapses.
func waitForReady(t *testing.T, pr *os.File, token string) {
	t.Helper()
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "READY "+token) {
				ch <- res{line: sc.Text()}
				return
			}
		}
		ch <- res{err: sc.Err()}
	}()

	select {
	case r := <-ch:
		if r.line == "" {
			t.Fatalf("helper exited before READY (scanner err: %v)", r.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("timed out waiting for descendant READY")
	}
}

// assertPipeEOF drains the pipe and requires it to reach EOF within the
// timeout. EOF means every process that inherited the write end (leader AND
// descendant) has exited, which is the portable, zombie-proof way to prove the
// descendant was actually killed.
func assertPipeEOF(t *testing.T, pr *os.File) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, pr)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("draining pipe to EOF failed: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("descendant still alive: pipe never reached EOF after kill")
	}
}

// Dispose() (timeout path) must terminate not just the leader but the
// descendant it spawned. unix relies on Kill(-pgid, SIGKILL); Windows on
// TerminateJobObject over a job attached pre-resume.
func TestProcessExitGroup_DisposeTerminatesDescendant(t *testing.T) {
	pg, cmd, pr := startLeaderWithDescendant(t, leaderModeStay, "dispose-tok")
	defer pr.Close()

	if err := pg.Dispose(); err != nil {
		t.Fatalf("Dispose: %v", err)
	}
	_ = cmd.Wait()

	assertPipeEOF(t, pr)
}

// ReapDescendants() (success path) must kill a descendant the leader left
// behind after the leader itself has already been reaped by cmd.Wait(). This
// is the exact mcp_handlers success branch: Wait the leader, then
// ReapDescendants to sweep orphaned grandchildren.
func TestProcessExitGroup_ReapDescendantsTerminatesDescendantAfterLeaderExit(t *testing.T) {
	pg, cmd, pr := startLeaderWithDescendant(t, leaderModeExit, "reap-tok")
	defer pr.Close()

	_ = cmd.Wait() // leader exits on its own in leaderModeExit
	pg.ReapDescendants()
	pg.Close()

	assertPipeEOF(t, pr)
}
