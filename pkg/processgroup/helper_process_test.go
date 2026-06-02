package processgroup

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Env contract for the helper subprocesses re-exec'd through the test binary.
// Tests set these before launching os.Executable() with -test.run pointed at
// one of the helper Test* functions below; the helpers no-op unless their gate
// env var is set, so a normal `go test` run never executes them.
const (
	envLeaderMode  = "PROCESSGROUP_TEST_LEADER"
	envDescToken   = "PROCESSGROUP_TEST_TOKEN"
	leaderModeStay = "leader-stay" // leader spawns descendant, then blocks forever
	leaderModeExit = "leader-exit" // leader spawns descendant, prints, then exits
)

// TestHelperLeaderProcess is re-exec'd as the "leader". It spawns a long-lived
// descendant that inherits stdout and emits READY <token>, then either blocks
// (leaderModeStay) or exits immediately (leaderModeExit). It is gated on
// envLeaderMode so it is inert during a normal test run.
func TestHelperLeaderProcess(t *testing.T) {
	mode := os.Getenv(envLeaderMode)
	if mode == "" {
		return
	}
	token := os.Getenv(envDescToken)

	desc := exec.Command(os.Args[0], "-test.run=^TestHelperDescendantProcess$")
	desc.Env = append(os.Environ(), envDescToken+"="+token, "PROCESSGROUP_TEST_DESC=1")
	desc.Stdout = os.Stdout
	desc.Stderr = os.Stderr
	if err := desc.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "leader: failed to start descendant: %v\n", err)
		os.Exit(2)
	}

	if mode == leaderModeExit {
		// Give the descendant a moment to print READY, then leave it orphaned
		// so the parent test can prove ReapDescendants() reaches it.
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}

	// leaderModeStay: keep the leader (and its inherited stdout write end) alive
	// until the parent kills the whole group. Sleep rather than select{} so the
	// runtime doesn't print a spurious "all goroutines asleep" deadlock fatal
	// when SIGKILL/TerminateJobObject arrives.
	time.Sleep(10 * time.Minute)
}

// TestHelperDescendantProcess is the grandchild. It announces readiness on
// stdout (so the parent can detect the EOF when it is killed) and then sleeps
// well past any test timeout. Gated on PROCESSGROUP_TEST_DESC.
func TestHelperDescendantProcess(t *testing.T) {
	if os.Getenv("PROCESSGROUP_TEST_DESC") == "" {
		return
	}
	token := os.Getenv(envDescToken)
	fmt.Printf("READY %s\n", token)
	_ = os.Stdout.Sync()
	time.Sleep(10 * time.Minute)
}
