//go:build unix && !aix

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

const (
	execOutputHelperModeEnv = "NEZHA_EXEC_OUTPUT_HELPER_MODE"
	execOutputHelperPIDEnv  = "NEZHA_EXEC_OUTPUT_HELPER_PID_FILE"
	execOutputHelperExact   = "exact-output"
	execOutputHelperRetain  = "retain-stdout"
	execOutputHelperTimeout = "retain-stdout-until-timeout"
	execOutputHelperBlock   = "block-until-killed"
	exactHelperStdout       = "stdout-final-byte\n"
	exactHelperStderr       = "stderr-final-byte\n"
)

func TestExecOutputHelperProcess(t *testing.T) {
	mode := os.Getenv(execOutputHelperModeEnv)
	if mode == "" {
		return
	}
	switch mode {
	case execOutputHelperExact:
		_, _ = fmt.Fprint(os.Stdout, exactHelperStdout)
		_, _ = fmt.Fprint(os.Stderr, exactHelperStderr)
		os.Exit(0)
	case execOutputHelperRetain:
		startRetainedStdoutDescendant()
		os.Exit(0)
	case execOutputHelperTimeout:
		startRetainedStdoutDescendant()
		waitForTerminationSignal()
	case execOutputHelperBlock:
		waitForTerminationSignal()
	default:
		os.Exit(2)
	}
}

func waitForTerminationSignal() {
	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, syscall.SIGTERM, syscall.SIGINT)
	<-terminated
}

func TestExecRetainedStdoutDescendant(t *testing.T) {
	pidFile := os.Getenv(execOutputHelperPIDEnv)
	if pidFile == "" {
		return
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(3)
	}
	ready := os.NewFile(3, "exec-output-ready")
	if ready == nil {
		os.Exit(4)
	}
	_, _ = ready.Write([]byte{1})
	_ = ready.Close()
	for {
		if _, err := os.Stdout.Write([]byte("retained-output\n")); err != nil {
			os.Exit(0)
		}
	}
}

func startRetainedStdoutDescendant() {
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		os.Exit(5)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestExecRetainedStdoutDescendant$")
	child.Env = append(os.Environ(), execOutputHelperPIDEnv+"="+os.Getenv(execOutputHelperPIDEnv))
	child.Stdout = os.Stdout
	child.ExtraFiles = []*os.File{readyWriter}
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		os.Exit(6)
	}
	_ = readyWriter.Close()
	var ready [1]byte
	if _, err := readyReader.Read(ready[:]); err != nil {
		os.Exit(7)
	}
	_ = readyReader.Close()
}

func executeOutputHelper(mode, pidFile string, timeoutSeconds uint32) model.ExecResult {
	return executeOutputHelperWithMaxOutput(mode, pidFile, timeoutSeconds, 4096)
}

func executeOutputHelperWithMaxOutput(mode, pidFile string, timeoutSeconds, maxOutputBytes uint32) model.ExecResult {
	request := model.ExecRequest{
		Cmd:            os.Args[0],
		Args:           []string{"-test.run=^TestExecOutputHelperProcess$"},
		Env:            map[string]string{execOutputHelperModeEnv: mode, execOutputHelperPIDEnv: pidFile},
		TimeoutSeconds: timeoutSeconds,
		MaxOutputBytes: maxOutputBytes,
	}
	body, err := json.Marshal(request)
	if err != nil {
		return model.ExecResult{ExitCode: -1, Error: err.Error()}
	}
	var taskResult pb.TaskResult
	handleExecTask(&pb.Task{Type: model.TaskTypeExec, Data: string(body)}, &taskResult)
	var result model.ExecResult
	if !taskResult.GetSuccessful() {
		return model.ExecResult{ExitCode: -1, Error: taskResult.GetData()}
	}
	if err := json.Unmarshal([]byte(taskResult.GetData()), &result); err != nil {
		return model.ExecResult{ExitCode: -1, Error: err.Error()}
	}
	return result
}

func setExecOutputLifecycleHook(t *testing.T, hook func(string)) {
	t.Helper()
	execOutputTestHookMu.Lock()
	previousHook := execOutputLifecycleHook
	execOutputLifecycleHook = hook
	t.Cleanup(func() {
		execOutputLifecycleHook = previousHook
		execOutputTestHookMu.Unlock()
	})
}

func awaitSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitExecResult(t *testing.T, result <-chan model.ExecResult) model.ExecResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for exec result")
		return model.ExecResult{}
	}
}

func awaitProcessExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("retained-pipe descendant %d still exists", pid)
		}
	}
}

var execOutputTestHookMu sync.Mutex
