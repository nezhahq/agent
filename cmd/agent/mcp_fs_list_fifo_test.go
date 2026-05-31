//go:build unix && !aix

package main

import (
	"encoding/json"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// fs.list must not open a non-directory target. Opening a FIFO read-only
// blocks until a writer appears, and the task runs in its own goroutine
// with no timeout, so a FIFO target would pin the goroutine indefinitely
// (remote DoS). The handler must Lstat first and reject non-directories
// promptly. fs.read already guards with Lstat+IsRegular; list must match.
func TestFsList_FifoReturnsPromptlyNotBlocked(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "hangfifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	req := model.FsListRequest{Path: fifo}
	body, _ := json.Marshal(req)
	task := &pb.Task{Type: model.TaskTypeFsList, Data: string(body)}

	done := make(chan model.FsListResult, 1)
	go func() {
		var res pb.TaskResult
		handleFsListTask(task, &res)
		var out model.FsListResult
		_ = json.Unmarshal([]byte(res.GetData()), &out)
		done <- out
	}()

	select {
	case out := <-done:
		if out.Error == "" {
			t.Fatalf("listing a FIFO must return an error, got entries=%d", len(out.Entries))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fs.list on a FIFO blocked: handler did not Lstat-guard the target")
	}
}
