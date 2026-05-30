package processgroup

import "testing"

// 在 Windows 上，NewProcessExitGroup 会持有一个 JobObject handle，
// AddProcess 再加上每个进程的 OpenProcess handle。成功执行路径上
// caller 调的是 ReapDescendants（只 TerminateJobObject），不会关闭
// 这些 handle。timeout 路径才走 Dispose() 关 handle。
//
// 这条测试约束的是「所有路径最终都必须能把 handle 释放」：
// 我们把句柄释放下沉到一个独立的 Close() 方法，ReapDescendants 只
// 负责整组 SIGKILL/TerminateJobObject，caller 显式调 Close() 关资源。
//
// 跨平台用 closed 标志位即可校验语义，不依赖真正的 Windows API。
func TestProcessExitGroup_CloseMarksReleased(t *testing.T) {
	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	if pg.IsClosed() {
		t.Fatalf("freshly created group must not be closed")
	}
	pg.Close()
	if !pg.IsClosed() {
		t.Fatalf("Close() must mark the group as closed so caller knows handles were released")
	}
	// Close 必须幂等：handler 在 timeout 分支调 Dispose 后再调 Close，
	// 或成功路径连续调用，都不能 panic / 双重 close 句柄。
	pg.Close()
}
