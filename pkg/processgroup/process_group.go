//go:build unix && !aix

package processgroup

import (
	"context"
	"os/exec"
	"sync"
	"syscall"
)

type ProcessExitGroup struct {
	cmds   []*exec.Cmd
	pgids  []int
	closed bool
}

func NewProcessExitGroup() (ProcessExitGroup, error) {
	return ProcessExitGroup{}, nil
}

// Close 与 Windows 端对齐。Unix 上 ProcessExitGroup 不持有内核句柄，
// 只把 closed 置位让上层流程能用同一段 defer 收尾，避免平台特化代码。
func (g *ProcessExitGroup) Close() {
	if g.closed {
		return
	}
	g.closed = true
}

func (g *ProcessExitGroup) IsClosed() bool { return g.closed }

func NewCommand(arg string) *exec.Cmd {
	cmd := exec.Command("sh", "-c", arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

// NewExecCommandContext 用于 MCP server.exec — 直接指定可执行文件 + args，
// 不经过 "sh -c"。保持 Setpgid=true，方便 ProcessExitGroup.Dispose 整组回收。
func NewExecCommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

// NewExecCommand: Setpgid=true, no context binding — caller owns timeout/cancel
// so exec.CommandContext can't race-kill the leader before our pgid-wide kill.
func NewExecCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func (g *ProcessExitGroup) Dispose() error {
	var wg sync.WaitGroup
	wg.Add(len(g.cmds))

	for i, c := range g.cmds {
		pgid := 0
		if i < len(g.pgids) {
			pgid = g.pgids[i]
		}
		go func(c *exec.Cmd, pgid int) {
			defer wg.Done()
			killChildProcess(c, pgid)
		}(c, pgid)
	}

	wg.Wait()
	return nil
}

// ReapDescendants 在 leader 已经被 cmd.Wait 收过的场景下使用。
// 仅向整组发 SIGKILL 让内核清掉孤立的孙子进程；不再调 c.Wait，
// 否则会和外层 cmd.Wait 形成 ECHILD 或被孙子持有的 stdout 阻塞。
func (g *ProcessExitGroup) ReapDescendants() {
	for i := range g.cmds {
		pgid := 0
		if i < len(g.pgids) {
			pgid = g.pgids[i]
		}
		if pgid > 0 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
	}
}

func (g *ProcessExitGroup) AddProcess(cmd *exec.Cmd) error {
	g.cmds = append(g.cmds, cmd)
	// Getpgid 失败时 pgid 保持 0，让 killChildProcess 走 c.Process.Kill
	// 单进程 fallback；不能把 pid 当作 pgid 存下来再执行 Kill(-pid)，否则
	// 会回到历史修复 0290813 (#123) 明确禁止的"对未验证 pid 发组 kill"路径。
	pgid := 0
	if cmd != nil && cmd.Process != nil {
		if p, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
			pgid = p
		}
	}
	g.pgids = append(g.pgids, pgid)
	return nil
}

// killChildProcess 只负责把整组杀掉，**不**调 c.Wait——收尸的责任在 caller
// （比如 mcp_handlers.handleExecTask 自己起 goroutine 跑 cmd.Wait）。Dispose
// 在这里重复 Wait 会和 caller 形成两次并发 Wait，os/exec 内部
// awaitGoroutines 通道接收会卡死整组 goroutine。
func killChildProcess(c *exec.Cmd, pgid int) {
	if pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	if c.Process != nil {
		_ = c.Process.Kill()
	}
}
