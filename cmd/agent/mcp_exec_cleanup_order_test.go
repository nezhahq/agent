package main

import (
	"encoding/json"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// 当 server.exec 走超时分支时，cleanup 顺序必须是：
//  1. 立刻把进程组/Job 杀掉（Linux: pgid SIGKILL；Windows: TerminateJobObject）
//  2. 之后才 cmd.Wait 收尸
//
// 旧实现是反过来——先 cmd.Wait 再 pg.Dispose。Linux 上 SIGKILL 整组之后
// cmd.Wait 能很快回来，Windows 上 cmd.Process.Kill() 只杀 leader，子孙若
// 还持有 stdout 管道，cmd.Wait 会被卡到 5min IO timeout，超时分支事实上失效。
//
// 这条测试用 hook 把内部 cleanup 顺序暴露给单元测试，确保两端在「超时」
// 路径上统一调用 pg.Dispose() 而不是单独的 leader kill。
func TestExec_TimeoutCleanupOrder_DisposeBeforeWait(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("hook fires on every platform; we run it on unix to keep CI single-platform")
	}

	var mu sync.Mutex
	var order []string
	prev := execTimeoutCleanupHook
	execTimeoutCleanupHook = func(stage string) {
		mu.Lock()
		order = append(order, stage)
		mu.Unlock()
	}
	t.Cleanup(func() { execTimeoutCleanupHook = prev })

	req := model.ExecRequest{
		Cmd:            "sh",
		Args:           []string{"-c", "sleep 5"},
		TimeoutSeconds: 1,
	}
	body, _ := json.Marshal(req)
	task := &pb.Task{Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult

	start := time.Now()
	handleExecTask(task, &res)
	elapsed := time.Since(start)

	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()

	if elapsed > 3*time.Second {
		t.Fatalf("timeout cleanup took %s; pg.Dispose must fire before cmd.Wait so child pipes close immediately",
			elapsed)
	}
	if len(got) < 2 {
		t.Fatalf("expected at least two cleanup stages, got %v", got)
	}
	if got[0] != "dispose" {
		t.Fatalf("first cleanup stage on timeout must be 'dispose' (kill job/process-group); got %v", got)
	}
	if got[1] != "wait" {
		t.Fatalf("second cleanup stage must be 'wait' (reap leader); got %v", got)
	}
}
