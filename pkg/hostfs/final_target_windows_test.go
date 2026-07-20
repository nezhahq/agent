//go:build windows

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredOpenDirectory_ordinary_windows_directory_succeeds(t *testing.T) {
	t.Parallel()

	anchor := newTestAnchor(t, t.TempDir())

	directory, err := anchor.OpenDirectory()
	if err != nil {
		t.Fatalf("OpenDirectory(): %v", err)
	}
	defer func() {
		if err := directory.Close(); err != nil {
			t.Errorf("close directory: %v", err)
		}
	}()
	info, err := directory.Stat()
	if err != nil {
		t.Fatalf("stat opened directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("opened mode = %s, want directory", info.Mode())
	}
}

func TestAnchoredRejectsFinal_reparse_point(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("[blocked: native reparse capability] create Windows symlink: %v", err)
	}
	anchor := newTestAnchor(t, link)

	targetType, err := anchor.ClassifyFinal()
	if err != nil {
		t.Fatalf("ClassifyFinal(): %v", err)
	}
	if targetType != FinalTargetSymlinkReparse {
		t.Fatalf("ClassifyFinal() = %v, want %v", targetType, FinalTargetSymlinkReparse)
	}
	file, err := anchor.OpenRegular()
	if file != nil {
		_ = file.Close()
		t.Fatalf("OpenRegular(reparse) file = %#v, want nil", file)
	}
	assertFinalTargetTypeError(t, err, FinalTargetRegular, FinalTargetSymlinkReparse)
}
