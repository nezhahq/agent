//go:build unix && !aix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// openDirNoFollow must open a real directory.
func TestOpenDirNoFollow_OpensDirectory(t *testing.T) {
	dir := t.TempDir()
	f, err := openDirNoFollow(dir)
	if err != nil {
		t.Fatalf("a directory must open, got %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() {
		t.Fatal("opened path must be a directory")
	}
}

// openDirNoFollow must refuse a FIFO without blocking. Opening a FIFO
// read-only normally blocks until a writer appears; the fs.list handler has
// no timeout, so a FIFO swapped in after the Lstat dir-check would pin the
// goroutine forever (remote DoS). The dir-open must be non-blocking and
// reject non-directories instead.
func TestOpenDirNoFollow_FifoDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "f")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		f, err := openDirNoFollow(fifo)
		if err == nil {
			f.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("opening a FIFO as a directory must fail, not succeed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("openDirNoFollow blocked on a FIFO; it must be non-blocking")
	}
}

// openDirNoFollow must refuse a symlinked directory (final-component symlink),
// closing the Lstat->Open TOCTOU.
func TestOpenDirNoFollow_RefusesSymlinkedDir(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "realdir")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	f, err := openDirNoFollow(link)
	if err == nil {
		f.Close()
		t.Fatal("openDirNoFollow must refuse a symlinked final component")
	}
}
