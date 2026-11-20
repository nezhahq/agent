package main

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

// The timeout watcher and the task goroutine both used to write result.Data.
// Run under -race this test fails on that unsynchronised write.
func TestCommandTask_TimeoutReportsWithoutRacingOnResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell command")
	}
	originalTimeout := commandTaskTimeout
	t.Cleanup(func() { commandTaskTimeout = originalTimeout })
	commandTaskTimeout = 200 * time.Millisecond

	var result pb.TaskResult
	handleCommandTaskWithConfig(taskFeatureGates{}, &pb.Task{Data: "echo started; sleep 30"}, &result)

	if result.GetSuccessful() {
		t.Fatal("a timed out command must not be reported as successful")
	}
	if !strings.HasPrefix(result.GetData(), "任务执行超时\n") {
		t.Fatalf("data = %q, want the timeout notice first", result.GetData())
	}
	if !strings.Contains(result.GetData(), "started") {
		t.Fatalf("data = %q, want the output captured before the timeout", result.GetData())
	}
}

func TestCommandTask_DisabledGateRunsNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell command")
	}
	marker := t.TempDir() + "/executed"

	var result pb.TaskResult
	handleCommandTaskWithConfig(taskFeatureGates{disableCommandExecute: true}, &pb.Task{Data: "touch " + marker}, &result)

	if result.GetSuccessful() {
		t.Fatal("command execution is disabled but the task reported success")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("command ran although command execution is disabled (stat err = %v)", err)
	}
}
