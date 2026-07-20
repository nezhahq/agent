package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureParent_candidateCloseFailureRemainsAnchorOwned(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	operations := anchor.descentOperations
	closeErr := errors.New("injected rejected candidate close failure")
	closeRoot := operations.closeRoot
	closeNative := operations.closeNativeDirectory
	var rejectedRoot *os.Root
	var rejectedNative *os.File
	rootCloseAttempts := 0
	nativeCloseAttempts := 0
	operations.sameFile = func(os.FileInfo, os.FileInfo) bool { return false }
	operations.openRoot = func(root *os.Root, name string) (*os.Root, error) {
		opened, err := (*os.Root).OpenRoot(root, name)
		if rejectedRoot == nil {
			rejectedRoot = opened
		}
		return opened, err
	}
	operations.openNativeDirectory = func(parent *os.File, name string) (*os.File, error) {
		opened, err := openNativeChildDirectory(parent, name)
		if rejectedNative == nil {
			rejectedNative = opened
		}
		return opened, err
	}
	operations.closeRoot = func(root *os.Root) error {
		if root == rejectedRoot {
			rootCloseAttempts++
			if rootCloseAttempts == 1 {
				return closeErr
			}
		}
		return closeRoot(root)
	}
	operations.closeNativeDirectory = func(file *os.File) error {
		if file == rejectedNative {
			nativeCloseAttempts++
			if nativeCloseAttempts == 1 {
				return closeErr
			}
		}
		return closeNative(file)
	}
	anchor.descentOperations = operations

	// When
	descentErr := anchor.EnsureParent(true, 0o755)

	// Then
	if !errors.Is(descentErr, closeErr) {
		t.Fatalf("EnsureParent() error = %v, want rejected candidate close failure", descentErr)
	}
	if len(anchor.retiredRoots) != 1 || len(anchor.retiredDirectories) != 1 {
		t.Fatalf("retired candidates = %d roots/%d directories, want 1/1", len(anchor.retiredRoots), len(anchor.retiredDirectories))
	}
	if _, statErr := os.Stat(filepath.Dir(target)); statErr != nil {
		t.Fatalf("created parent disappeared after candidate rejection: %v", statErr)
	}
	if err := anchor.Close(); err != nil {
		t.Fatalf("Anchor.Close() retry: %v", err)
	}
	if rootCloseAttempts != 2 || nativeCloseAttempts != 2 {
		t.Fatalf("candidate close attempts = %d/%d, want 2/2", rootCloseAttempts, nativeCloseAttempts)
	}
}
