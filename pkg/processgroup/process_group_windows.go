//go:build windows

package processgroup

import (
	"context"
	"fmt"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProcessExitGroup struct {
	cmds      []*exec.Cmd
	jobHandle windows.Handle
	procs     []windows.Handle
	closed    bool
}

func NewProcessExitGroup() (*ProcessExitGroup, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}

	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info))); err != nil {
		// 没装 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 的 job 在 Close 时不会
		// 杀掉成员进程；继续返回这种 job 等于偷偷退化成「无 reaper」语义，
		// 上游 MCP exec 超时/异常时会留下孤儿进程。直接释放并向上报错。
		windows.CloseHandle(job)
		return nil, err
	}

	return &ProcessExitGroup{jobHandle: job}, nil
}

func NewCommand(args string) *exec.Cmd {
	cmd := exec.Command("cmd")
	cmd.SysProcAttr = &windows.SysProcAttr{
		CmdLine:       fmt.Sprintf("/c %s", args),
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd
}

// NewExecCommandContext is the Windows counterpart of the unix variant; it
// builds a job-killable command for the MCP server.exec path.
func NewExecCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd
}

// NewExecCommand mirrors the unix variant: CREATE_NEW_PROCESS_GROUP without
// binding a context so the caller owns timeout/cancel.
func NewExecCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd
}

func (g *ProcessExitGroup) AddProcess(cmd *exec.Cmd) error {
	proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.PROCESS_SET_QUOTA|windows.PROCESS_SET_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}

	g.procs = append(g.procs, proc)
	g.cmds = append(g.cmds, cmd)

	return windows.AssignProcessToJobObject(g.jobHandle, proc)
}

// ReapDescendants terminates the JobObject so any descendants the leader left
// behind are killed by the kernel. Used in the success path where cmd.Wait
// has already reaped the leader; calling Dispose() there would block on
// WaitForSingleObject for an already-dead job and double-close the handle.
//
// ReapDescendants 只 kill，**不**释放 jobHandle/procs；caller 必须在所有
// 路径上配一次 Close()，否则每个 exec 会泄漏一个 job + N 个 proc 句柄。
func (g *ProcessExitGroup) ReapDescendants() {
	if g.closed {
		return
	}
	_ = windows.TerminateJobObject(g.jobHandle, 1)
}

// Close 释放 JobObject 与所有进程句柄，idempotent。
// 单独成方法的目的：成功路径走 ReapDescendants→Close，timeout 路径走
// Dispose→Close 都能让 caller 用同一个 defer 释放，不再依赖 Dispose 的
// fall-through 完成资源回收。
func (g *ProcessExitGroup) Close() {
	if g.closed {
		return
	}
	g.closed = true
	windows.CloseHandle(g.jobHandle)
	for _, proc := range g.procs {
		windows.CloseHandle(proc)
	}
}

func (g *ProcessExitGroup) IsClosed() bool { return g.closed }

// disposeJobWaitTimeoutMs caps the post-terminate wait. TerminateJobObject is
// synchronous-ish but the handle signal can still stall on a wedged driver or
// an unkillable (uninterruptible-IO) member. An INFINITE wait there hangs the
// MCP exec timeout branch — which calls Dispose() synchronously — so the
// 2-second guard around cmd.Wait() never gets to run and the handler never
// returns. A bounded wait keeps timeout cleanup non-blocking; KILL_ON_JOB_CLOSE
// plus the deferred Close() still reap the job if the wait gives up early.
const disposeJobWaitTimeoutMs = 5000

func (g *ProcessExitGroup) Dispose() error {
	if g.closed {
		return nil
	}
	defer g.Close()

	if err := windows.TerminateJobObject(g.jobHandle, 1); err != nil {
		// Fall-back on error. Kill the main process only.
		for _, cmd := range g.cmds {
			cmd.Process.Kill()
		}
		return err
	}

	// wait for job to be terminated, but never block forever
	status, err := windows.WaitForSingleObject(g.jobHandle, disposeJobWaitTimeoutMs)
	if status != windows.WAIT_OBJECT_0 {
		return err
	}

	return nil
}
