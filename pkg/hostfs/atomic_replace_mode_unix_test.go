//go:build unix

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredAtomicReplace_AppliesRequestedUnixMode(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "created.txt")
	anchor := newTestAnchor(t, target)

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o640)

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("stat target: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("target mode = %o, want 640", got)
	}
}
