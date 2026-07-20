package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureParent_syncFailurePreservesAnchorForRetry(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	oldRoot := anchor.Root()
	oldNative := anchor.NativeDirectory()
	syncErr := errors.New("injected parent sync failure")
	operations := anchor.descentOperations
	syncCalls := 0
	operations.syncDirectory = func(directory *os.File) error {
		syncCalls++
		if syncCalls == 1 {
			return syncErr
		}
		return nil
	}
	mkdir := operations.mkdir
	operations.mkdir = func(root *os.Root, name string, mode os.FileMode) error {
		if err := mkdir(root, name, mode); err != nil {
			return err
		}
		if syncCalls == 1 {
			return nil
		}
		return os.ErrExist
	}
	anchor.descentOperations = operations

	// When
	firstErr := anchor.EnsureParent(true, 0o755)

	// Then
	if !errors.Is(firstErr, syncErr) {
		t.Fatalf("first EnsureParent() error = %v, want sync failure", firstErr)
	}
	if anchor.Root() != oldRoot || anchor.NativeDirectory() != oldNative {
		t.Fatal("sync failure replaced the retained anchor handles")
	}
	if got := anchor.MissingParents(); len(got) != 1 || got[0] != "missing" {
		t.Fatalf("missing parents after sync failure = %v, want [missing]", got)
	}
	if _, statErr := os.Stat(filepath.Dir(target)); statErr != nil {
		t.Fatalf("created parent disappeared after sync failure: %v", statErr)
	}

	// When
	secondErr := anchor.EnsureParent(true, 0o755)

	// Then
	if secondErr != nil {
		t.Fatalf("retry EnsureParent(): %v", secondErr)
	}
	if syncCalls != 2 {
		t.Fatalf("sync calls = %d, want 2", syncCalls)
	}
	if len(anchor.MissingParents()) != 0 {
		t.Fatalf("missing parents after retry = %v, want none", anchor.MissingParents())
	}
}

func TestEnsureParent_syncsEveryAdoptedParent(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "first", "second", "target.txt")
	anchor := newTestAnchor(t, target)
	operations := anchor.descentOperations
	syncCalls := 0
	operations.syncDirectory = func(*os.File) error {
		syncCalls++
		return nil
	}
	anchor.descentOperations = operations

	// When
	err := anchor.EnsureParent(true, 0o755)

	// Then
	if err != nil {
		t.Fatalf("EnsureParent(): %v", err)
	}
	if syncCalls != 2 {
		t.Fatalf("sync calls = %d, want one sync for each missing parent", syncCalls)
	}
}
