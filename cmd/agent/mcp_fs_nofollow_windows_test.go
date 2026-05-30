//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRegularNoFollow_RefusesSymlinkWindows(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink (needs privilege): %v", err)
	}

	f, err := openRegularNoFollow(link)
	if err == nil {
		f.Close()
		t.Fatal("openRegularNoFollow must refuse a symlink/reparse-point final component on Windows")
	}
}

func TestOpenRegularNoFollow_OpensRegularFileWindows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "file")
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := openRegularNoFollow(p)
	if err != nil {
		t.Fatalf("a regular file must open, got %v", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatal("opened file must be regular")
	}
}
