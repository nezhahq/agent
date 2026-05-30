package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// 让 sh 主进程立即退出，但生成一个孙进程 sleep 30s 后 touch sentinel。
// 超时 1s 后 pg.Dispose 应当杀掉整个进程组，sentinel 永远不应该出现。
// 当前实现是先 cmd.Wait 再 Dispose，孙子进程不与 stdout 关联时 Wait 立刻
// 返回 → Dispose 也立刻执行 → 孙进程被 SIGTERM。
// 真正会逃逸的是“孙进程持有 stdout 管道”的场景：sh -c "sleep 5"（没有
// 后台 &），shell 被 SIGKILL 时其子 sleep 也跟随 setpgid 被收到 SIGTERM。
// 因此构造一个能稳定复现“逃逸”的命令需要 PTY 或显式 detach。
// 我们改用更扎实的不变量：超时后 handler 返回耗时应当 ≈ 超时时间，而不是
// 等到子进程自然退出。这个测试若 cmd.Wait 等待子进程 stdout 关闭，会显著
// 超过 1s。
func TestExec_TimeoutReturnsPromptly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only timeout semantics")
	}
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "child-alive")

	req := model.ExecRequest{
		Cmd:            "sh",
		Args:           []string{"-c", "sleep 6 && touch " + sentinel},
		TimeoutSeconds: 1,
	}
	body, _ := json.Marshal(req)
	task := &pb.Task{Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult

	start := time.Now()
	handleExecTask(task, &res)
	elapsed := time.Since(start)

	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if !out.TimedOut {
		t.Fatalf("expected timed_out=true, got %+v", out)
	}

	if elapsed > 3*time.Second {
		t.Fatalf("handler took %s; expected close to 1s timeout — child likely kept pipe open and blocked cmd.Wait", elapsed)
	}

	// 命令是 `sleep 6 && touch sentinel`：必须等过 6s 才能区分“sleep 被进程组
	// SIGKILL 提前结束 → 永远不 touch” vs “sleep 没被杀 → 6s 后 touch”。
	time.Sleep(7 * time.Second)
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatalf("child process completed after timeout; process group was not killed in time")
	}
}
