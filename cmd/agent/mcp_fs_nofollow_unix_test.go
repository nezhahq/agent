//go:build unix && !aix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// openRegularNoFollow must refuse to open a path whose final component is a
// symlink, closing the Lstat->Open TOCTOU where an attacker swaps a regular
// file for a symlink to a sensitive target between the check and the open.
func TestOpenRegularNoFollow_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "secret")
	if err := os.WriteFile(target, []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	f, err := openRegularNoFollow(link)
	if err == nil {
		f.Close()
		t.Fatal("openRegularNoFollow must refuse a symlink final component")
	}
}

func TestOpenRegularNoFollow_OpensRegularFile(t *testing.T) {
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
