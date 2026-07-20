package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/processgroup"
	pb "github.com/nezhahq/agent/proto"
)

const (
	mcpExecDefaultTimeoutSec = 30
	mcpExecMaxTimeoutSec     = 300
	mcpExecDefaultMaxOutput  = 64 * 1024
	mcpExecAbsoluteMaxOutput = 1 * 1024 * 1024
)

var execTimeoutCleanupHook = func(stage string) {}

// execOutputLifecycleHook exposes exec pipe-copy ordering to deterministic
// tests. Production leaves it as a no-op.
var execOutputLifecycleHook = func(stage string) {}

// execSuccessfulDrainGrace bounds only post-exit pipe draining. The process is
// already reaped; 500ms lets runnable copy goroutines consume kernel-buffered
// bytes without allowing an escaped inherited writer to pin server.exec.
var execSuccessfulDrainGrace = 500 * time.Millisecond

// execPostKillWaitGrace preserves the existing two-second best-effort reap
// bound while making the timeout cleanup contract explicit and testable.
var execPostKillWaitGrace = 2 * time.Second

func killAndReapAfterStart(cmd *exec.Cmd, pgid int) {
	killProcessGroupHard(cmd, pgid)
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Wait()
	}
}

func handleExecTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableCommandExecute {
		mcpReply(result, model.ExecResult{Error: "agent disabled command execution"})
		return
	}
	var request model.ExecRequest
	if err := json.Unmarshal([]byte(task.GetData()), &request); err != nil {
		mcpReplyError(result, "invalid exec request: "+err.Error())
		return
	}
	if strings.TrimSpace(request.Cmd) == "" {
		mcpReply(result, model.ExecResult{Error: "cmd required"})
		return
	}

	timeoutSeconds := request.TimeoutSeconds
	if timeoutSeconds == 0 {
		timeoutSeconds = mcpExecDefaultTimeoutSec
	}
	if timeoutSeconds > mcpExecMaxTimeoutSec {
		timeoutSeconds = mcpExecMaxTimeoutSec
	}
	maxOutputBytes := int(request.MaxOutputBytes)
	if maxOutputBytes == 0 {
		maxOutputBytes = mcpExecDefaultMaxOutput
	}
	if maxOutputBytes > mcpExecAbsoluteMaxOutput {
		maxOutputBytes = mcpExecAbsoluteMaxOutput
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cmd := processgroup.NewSuspendedExecCommand(request.Cmd, request.Args...)
	cmd.Dir = request.Cwd
	cmd.Env = mcpExecEnv(request.Env)
	if request.Stdin != "" {
		cmd.Stdin = strings.NewReader(request.Stdin)
	}
	stdoutBuffer := &truncatingBuffer{max: maxOutputBytes}
	stderrBuffer := &truncatingBuffer{max: maxOutputBytes}

	stdoutReader, stdoutWriter, pipeErr := os.Pipe()
	if pipeErr != nil {
		mcpReply(result, model.ExecResult{Error: execErrMsg(pipeErr)})
		return
	}
	stderrReader, stderrWriter, pipeErr := os.Pipe()
	if pipeErr != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		mcpReply(result, model.ExecResult{Error: execErrMsg(pipeErr)})
		return
	}
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter
	var closeReadersOnce sync.Once
	closeReaders := func() {
		closeReadersOnce.Do(func() {
			_ = stdoutReader.Close()
			_ = stderrReader.Close()
		})
	}

	processExitGroup, groupErr := processgroup.NewProcessExitGroup()
	if groupErr != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
		mcpReply(result, model.ExecResult{Error: execErrMsg(groupErr)})
		return
	}
	defer processExitGroup.Close()

	startedAt := time.Now()
	if err := cmd.Start(); err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		_ = stderrReader.Close()
		_ = stderrWriter.Close()
		mcpReply(result, model.ExecResult{ExitCode: -1, Error: execErrMsg(err)})
		return
	}
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()

	processGroupID := processGroupID(cmd)
	if err := processExitGroup.AddProcess(cmd); err != nil {
		killAndReapAfterStart(cmd, processGroupID)
		closeReaders()
		mcpReply(result, model.ExecResult{ExitCode: -1, Error: execErrMsg(err)})
		return
	}
	if err := processgroup.ResumeMainThread(cmd); err != nil {
		killAndReapAfterStart(cmd, processGroupID)
		closeReaders()
		mcpReply(result, model.ExecResult{ExitCode: -1, Error: execErrMsg(err)})
		return
	}

	copyDone := make(chan struct{}, 2)
	go func() {
		execOutputLifecycleHook("stdout-copy-start")
		_, _ = io.Copy(stdoutBuffer, stdoutReader)
		execOutputLifecycleHook("stdout-copy-done")
		copyDone <- struct{}{}
	}()
	go func() {
		execOutputLifecycleHook("stderr-copy-start")
		_, _ = io.Copy(stderrBuffer, stderrReader)
		execOutputLifecycleHook("stderr-copy-done")
		copyDone <- struct{}{}
	}()

	waitErrCh := make(chan error, 1)
	go func() { waitErrCh <- cmd.Wait() }()

	var runErr error
	completedCopies := 0
	select {
	case runErr = <-waitErrCh:
		execOutputLifecycleHook("process-waited")
		processExitGroup.ReapDescendants()
		// A successful Wait reaps the process but does not mean concurrent pipe
		// readers have consumed every byte already buffered by the kernel.
		execOutputLifecycleHook("success-drain-start")
		drainTimer := time.NewTimer(execSuccessfulDrainGrace)
	drainLoop:
		for completedCopies < 2 {
			select {
			case <-copyDone:
				completedCopies++
			case <-drainTimer.C:
				break drainLoop
			}
		}
		if !drainTimer.Stop() {
			select {
			case <-drainTimer.C:
			default:
			}
		}
	case <-ctx.Done():
		execTimeoutCleanupHook("dispose")
		_ = processExitGroup.Dispose()
		closeReaders()
		execTimeoutCleanupHook("wait")
		select {
		case runErr = <-waitErrCh:
		case <-time.After(execPostKillWaitGrace):
			runErr = errors.New("cmd.Wait pinned after kill; pipe close forced abort")
		}
	}
	closeReaders()
	for completedCopies < 2 {
		<-copyDone
		completedCopies++
	}

	response := model.ExecResult{
		Stdout:          stdoutBuffer.buf.String(),
		Stderr:          stderrBuffer.buf.String(),
		DurationMs:      time.Since(startedAt).Milliseconds(),
		StdoutTruncated: stdoutBuffer.full,
		StderrTruncated: stderrBuffer.full,
	}
	if ctx.Err() == context.DeadlineExceeded {
		response.TimedOut = true
	}
	if runErr != nil {
		var exitError *exec.ExitError
		if errors.As(runErr, &exitError) {
			response.ExitCode = exitError.ExitCode()
		} else {
			response.ExitCode = -1
			response.Error = execErrMsg(runErr)
		}
	}
	mcpReply(result, response)
}
