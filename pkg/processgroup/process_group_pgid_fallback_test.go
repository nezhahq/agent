//go:build unix && !aix

package processgroup

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// 历史修复 0290813 "fix: do not kill wrong process group (#123)" 明确：
// 拿不到合法的 pgid 时**不能**对负 pid 发 kill，否则可能误杀 PID==pgid
// 重名的其他进程组（极端时甚至 -1 触达 init / 整个会话）。
//
// 当前 AddProcess 在 syscall.Getpgid 失败时把 pgid 回退成 pid 并保存到
// g.pgids；后续 Dispose / ReapDescendants 会执行 syscall.Kill(-pgid, ...)，
// 等价于历史修复禁止的“对未验证的 pid 发组 kill”。
//
// 这条测试把契约固化为：Getpgid 失败 → 记录的 pgid 必须是 0（让
// killChildProcess 走 c.Process.Kill 这条单进程 fallback），不能等于 pid。
func TestAddProcess_GetpgidFailureDoesNotFallBackToPid(t *testing.T) {
	t.Parallel()

	// 用一个绝对不会有效的 PID 触发 Getpgid 失败。
	// Linux/Darwin 上 Getpgid 对负 pid / 不存在的进程返回 EINVAL/ESRCH。
	// 我们不真去 fork，只是给 exec.Cmd 挂一个 fake Process，让 AddProcess
	// 走 “有 Process 但 Getpgid 失败” 这条分支。
	const sentinelPid = -424242
	if _, err := syscall.Getpgid(sentinelPid); err == nil {
		t.Skipf("Getpgid(%d) unexpectedly succeeded on this kernel; pick a different sentinel PID", sentinelPid)
	}
	cmd := &exec.Cmd{Process: &os.Process{Pid: sentinelPid}}

	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	if err := pg.AddProcess(cmd); err != nil {
		t.Fatalf("AddProcess: %v", err)
	}

	if len(pg.pgids) != 1 {
		t.Fatalf("expected exactly one pgid slot, got %d", len(pg.pgids))
	}
	if pg.pgids[0] != 0 {
		t.Fatalf("Getpgid failure must leave pgid=0 so killChildProcess falls back to c.Process.Kill; got pgid=%d (== pid? %v)",
			pg.pgids[0], pg.pgids[0] == cmd.Process.Pid)
	}
}
