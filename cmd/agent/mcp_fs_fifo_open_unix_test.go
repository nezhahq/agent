//go:build unix && !aix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Opening a FIFO nobody writes to blocks. The if_match check of an upload did
// that while holding the path lock, and nothing bounded the wait for that lock
// before a reconnect, so one such request kept the agent offline until restart.
func TestSha256OfFile_FIFOWithoutWriterIsRefusedInsteadOfBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "never-written.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := sha256OfFile(fifo)
		finished <- err
	}()

	select {
	case err := <-finished:
		if !errors.Is(err, errNotARegularFile) {
			t.Fatalf("err = %v, want errNotARegularFile", err)
		}
	case <-time.After(3 * time.Second):
		// Unblock the opener so the test process can exit.
		if writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = writer.Close()
		}
		t.Fatal("hashing a FIFO without a writer blocked")
	}
}

func TestOpenRegularNoFollow_RegularFileReadsNormally(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular.txt")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	digest, err := sha256OfFile(path)

	const sha256OfContent = "ed7002b439e9ac845f22357d822bac1444730fbdb6016d3ec9432297b9ec9f73"
	if err != nil || digest != sha256OfContent {
		t.Fatalf("sha256OfFile = %q, %v; want %q", digest, err, sha256OfContent)
	}
}
