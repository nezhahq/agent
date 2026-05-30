package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

// M5 regression: after a successful rename, the agent must fsync the
// parent directory so a crash cannot lose the directory entry. The
// success reply happens before the entry is durable, which makes the
// API stronger than what the kernel actually guarantees on POSIX.
func TestFsyncDir_SucceedsOnExistingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only durability primitive; Windows fsyncs metadata via the file handle")
	}
	dir := t.TempDir()
	if err := fsyncDir(dir); err != nil {
		t.Fatalf("fsyncDir on a real directory must succeed, got %v", err)
	}
}

func TestFsyncDir_ReturnsErrorOnMissingDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX-only durability primitive")
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if err := fsyncDir(missing); err == nil {
		t.Fatal("fsyncDir on a missing directory must surface an error so callers can decide what to do")
	}
}
