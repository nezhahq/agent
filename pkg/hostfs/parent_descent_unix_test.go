//go:build unix

package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredCreateDirs_ParentPathReplacementCannotRedirect(t *testing.T) {
	// Given
	base := t.TempDir()
	originalParent := filepath.Join(base, "parent")
	if err := os.Mkdir(originalParent, 0o755); err != nil {
		t.Fatalf("mkdir original parent: %v", err)
	}
	target := filepath.Join(originalParent, "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	movedParent := filepath.Join(base, "moved")
	if err := os.Rename(originalParent, movedParent); err != nil {
		t.Fatalf("rename anchored parent: %v", err)
	}
	if err := os.Mkdir(originalParent, 0o755); err != nil {
		t.Fatalf("mkdir replacement parent: %v", err)
	}

	// When
	err := anchor.EnsureParent(true, 0o755)

	// Then
	if err != nil {
		t.Fatalf("EnsureParent(): %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(movedParent, "missing")); statErr != nil {
		t.Fatalf("anchored child missing from original directory: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(originalParent, "missing")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("replacement pathname was mutated: %v", statErr)
	}
}

func TestAnchoredCreateDirs_RejectsConcurrentLinkInsertion(t *testing.T) {
	// Given
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	target := filepath.Join(base, "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	operations := anchor.descentOperations
	mkdir := operations.mkdir
	operations.mkdir = func(root *os.Root, name string, mode os.FileMode) error {
		if err := mkdir(root, name, mode); err != nil {
			return err
		}
		if err := root.Remove(name); err != nil {
			return err
		}
		if err := root.Symlink(outside, name); err != nil {
			return err
		}
		return os.ErrExist
	}
	anchor.descentOperations = operations

	// When
	err := anchor.EnsureParent(true, 0o755)

	// Then
	if err == nil || errors.Is(err, ErrHandleMismatch) {
		t.Fatalf("EnsureParent() error = %v, want native no-follow rejection", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "target.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("link target was mutated: %v", statErr)
	}
}
