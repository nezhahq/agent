//go:build unix && !aix

package main

import (
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

func TestExecSuccessfulExitDrainsOutputBeforeClosingPipes(t *testing.T) {
	copyPermit := make(chan struct{})
	copyStarted := make(chan struct{}, 2)
	processWaited := make(chan struct{}, 1)
	successDrainStarted := make(chan struct{}, 1)
	setExecOutputLifecycleHook(t, func(stage string) {
		switch stage {
		case "stdout-copy-start", "stderr-copy-start":
			copyStarted <- struct{}{}
			<-copyPermit
		case "process-waited":
			processWaited <- struct{}{}
		case "success-drain-start":
			successDrainStarted <- struct{}{}
		}
	})

	resultDone := make(chan model.ExecResult, 1)
	go func() {
		resultDone <- executeOutputHelper(execOutputHelperExact, "", 5)
	}()

	awaitSignal(t, processWaited, "process wait")
	awaitSignal(t, copyStarted, "stdout copy start")
	awaitSignal(t, copyStarted, "stderr copy start")
	select {
	case <-successDrainStarted:
	case <-time.After(25 * time.Millisecond):
	}
	close(copyPermit)

	result := awaitExecResult(t, resultDone)
	if result.Stdout != exactHelperStdout {
		t.Fatalf("stdout = %q, want exact final bytes %q", result.Stdout, exactHelperStdout)
	}
	if result.Stderr != exactHelperStderr {
		t.Fatalf("stderr = %q, want exact final bytes %q", result.Stderr, exactHelperStderr)
	}
	t.Logf("exact stdout=%q stderr=%q", result.Stdout, result.Stderr)
}

func TestExecSuccessfulExitBoundsDrainWhenDescendantRetainsPipe(t *testing.T) {
	pidFile := t.TempDir() + "/retained-pipe.pid"
	copyDone := make(chan struct{}, 2)
	successDrainStarted := make(chan struct{}, 1)
	setExecOutputLifecycleHook(t, func(stage string) {
		switch stage {
		case "stdout-copy-done", "stderr-copy-done":
			copyDone <- struct{}{}
		case "success-drain-start":
			successDrainStarted <- struct{}{}
		}
	})
	previousGrace := execSuccessfulDrainGrace
	execSuccessfulDrainGrace = 25 * time.Millisecond
	t.Cleanup(func() { execSuccessfulDrainGrace = previousGrace })

	resultDone := make(chan model.ExecResult, 1)
	go func() {
		resultDone <- executeOutputHelper(execOutputHelperRetain, pidFile, 5)
	}()
	awaitSignal(t, successDrainStarted, "retained-pipe success drain start")
	drainStartedAt := time.Now()
	result := awaitExecResult(t, resultDone)
	drainElapsed := time.Since(drainStartedAt)
	if result.TimedOut || result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("retained-pipe success result changed: %+v", result)
	}
	if drainElapsed > 500*time.Millisecond {
		t.Fatalf("bounded successful drain took %s", drainElapsed)
	}
	awaitSignal(t, copyDone, "stdout copy completion")
	awaitSignal(t, copyDone, "stderr copy completion")
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read retained descendant pid: %v", err)
	}
	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		t.Fatalf("parse retained descendant pid: %v", err)
	}
	awaitProcessExit(t, pid)
	t.Logf("retained-pipe drain elapsed=%s descendant_pid=%d cleanup=exited", drainElapsed, pid)
}

func TestExecTimeoutRemainsPromptAndExact(t *testing.T) {
	copyDone := make(chan struct{}, 2)
	setExecOutputLifecycleHook(t, func(stage string) {
		if stage == "stdout-copy-done" || stage == "stderr-copy-done" {
			copyDone <- struct{}{}
		}
	})

	startedAt := time.Now()
	result := executeOutputHelper(execOutputHelperBlock, "", 1)
	elapsed := time.Since(startedAt)
	if !result.TimedOut || result.ExitCode != -1 || result.Error != "" {
		t.Fatalf("timeout result = %+v, want TimedOut=true ExitCode=-1 Error empty", result)
	}
	if elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("timeout cleanup elapsed = %s, want prompt return near 1s", elapsed)
	}
	awaitSignal(t, copyDone, "stdout timeout copy completion")
	awaitSignal(t, copyDone, "stderr timeout copy completion")
}
