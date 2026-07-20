//go:build unix && !aix

package fm

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
	"golang.org/x/sys/unix"
)

func TestTask_CancelableDownloadOpen_FIFOWithoutWriterShutsDownBoundedly(t *testing.T) {
	// Given
	fifoPath := filepath.Join(t.TempDir(), "download.fifo")
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	task := NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         &serialTaskSender{downloadSent: make(chan struct{})},
		UploadReceiver: &legacyUploadReceiver{},
		Printf:         func(string, ...interface{}) {},
	})
	if err := task.DoTask(&pb.IOStreamData{Data: append([]byte{byte(commandDownload)}, fifoPath...)}); err != nil {
		t.Fatalf("start FIFO download: %v", err)
	}
	shutdownDone := make(chan struct{})

	// When
	go func() {
		task.Shutdown(context.Canceled)
		close(shutdownDone)
	}()

	// Then
	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		t.Fatal("FIFO download blocked before registration and prevented bounded shutdown")
	}
	if active := task.active.Load(); active != 0 {
		t.Fatalf("active FIFO download producers after shutdown = %d, want 0", active)
	}
}
