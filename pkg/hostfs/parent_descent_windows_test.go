//go:build windows

package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAnchoredCreateDirs_OpenParentRenameIsDenied(t *testing.T) {
	// Given
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	newTestAnchor(t, filepath.Join(parent, "missing", "target.txt"))

	// When
	err := os.Rename(parent, filepath.Join(filepath.Dir(parent), "moved"))

	// Then
	if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("rename open anchored parent error = %v, want ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION", err)
	}
}
