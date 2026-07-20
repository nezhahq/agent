package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestAnchoredAtomicReplace_CleanupOwnershipEndsAtRename(t *testing.T) {
	t.Parallel()

	t.Run("pre-rename failure refuses cleanup once", func(t *testing.T) {
		// Given
		directory := t.TempDir()
		target := filepath.Join(directory, "pre-rename.txt")
		writeTestFile(t, target, "old-content")
		anchor := newTestAnchor(t, target)
		operations := anchor.atomicOperations
		cleanupCalls := 0
		operations.cleanupTemp = func() error {
			cleanupCalls++
			return ErrAtomicTempCleanupRefused
		}
		operations.rename = func(*os.Root, string, string) error {
			return errors.New("injected rename failure")
		}
		anchor.atomicOperations = operations

		// When
		result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

		// Then
		if result.Committed || !errors.Is(err, ErrAtomicTempCleanupRefused) || cleanupCalls != 1 {
			t.Fatalf("result/error/cleanup calls = %+v/%v/%d, want uncommitted cleanup refusal", result, err, cleanupCalls)
		}
	})

	t.Run("post-rename failure never removes", func(t *testing.T) {
		// Given
		directory := t.TempDir()
		target := filepath.Join(directory, "post-rename.txt")
		writeTestFile(t, target, "old-content")
		anchor := newTestAnchor(t, target)
		operations := anchor.atomicOperations
		cleanupCalls := 0
		operations.cleanupTemp = func() error {
			cleanupCalls++
			return nil
		}
		operations.syncDirectory = func(*os.File) error {
			return errors.New("injected directory sync failure")
		}
		anchor.atomicOperations = operations

		// When
		result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

		// Then
		if !result.Committed || !errors.Is(err, ErrCommittedDurabilityUnknown) || cleanupCalls != 0 {
			t.Fatalf("result/error/cleanup calls = %+v/%v/%d, want committed error and no cleanup", result, err, cleanupCalls)
		}
		assertFileContent(t, target, "new-content")
	})
}

func TestAnchoredAtomicReplace_TempCollisionDoesNotRemoveCompetingEntry(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "collision.txt")
	anchor := newTestAnchor(t, target)
	collisionName := atomicTempPrefix() + "collision"
	collisionPath := filepath.Join(directory, collisionName)
	writeTestFile(t, collisionPath, "competing-temp")
	operations := anchor.atomicOperations
	operations.temporaryName = func() (string, error) { return collisionName, nil }
	cleanupCalls := 0
	operations.cleanupTemp = func() error {
		cleanupCalls++
		return nil
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	if result.Committed || !errors.Is(err, os.ErrExist) || cleanupCalls != 0 {
		t.Fatalf("result/error/cleanup calls = %+v/%v/%d, want collision without cleanup ownership", result, err, cleanupCalls)
	}
	assertFileContent(t, collisionPath, "competing-temp")
}

func TestAnchoredAtomicReplace_OrdersRevalidationImmediatelyBeforeRename(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "ordered.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	events := make([]string, 0, 7)
	writeFile := operations.writeFile
	chmodFile := operations.chmodFile
	syncFile := operations.syncFile
	closeFile := operations.closeFile
	revalidateFinal := operations.revalidateFinal
	rename := operations.rename
	syncDirectory := operations.syncDirectory
	operations.writeFile = func(file *os.File, data []byte) error {
		events = append(events, "write")
		return writeFile(file, data)
	}
	operations.chmodFile = func(file *os.File, mode os.FileMode) error {
		events = append(events, "chmod")
		return chmodFile(file, mode)
	}
	operations.syncFile = func(file *os.File) error {
		events = append(events, "file-sync")
		return syncFile(file)
	}
	operations.closeFile = func(file *os.File) error {
		events = append(events, "close")
		return closeFile(file)
	}
	operations.revalidateFinal = func(anchor *Anchor) (FinalTargetType, error) {
		events = append(events, "revalidate")
		return revalidateFinal(anchor)
	}
	operations.rename = func(root *os.Root, oldName, newName string) error {
		events = append(events, "rename")
		return rename(root, oldName, newName)
	}
	operations.syncDirectory = func(directory *os.File) error {
		events = append(events, "directory-sync")
		return syncDirectory(directory)
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
	want := []string{"write", "chmod", "file-sync", "close", "revalidate", "rename", "directory-sync"}
	if !slices.Equal(events, want) {
		t.Fatalf("operation order = %v, want %v", events, want)
	}
}
