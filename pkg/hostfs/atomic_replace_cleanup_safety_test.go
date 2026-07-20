package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredAtomicReplace_RefusesCleanupAfterTemporaryNameReplacement(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	openFile := operations.openFile
	var temporaryName string
	operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
		temporaryName = name
		return openFile(root, name, flag, mode)
	}
	primaryErr := errors.New("injected revalidation failure")
	operations.revalidateFinal = func(*Anchor) (FinalTargetType, error) {
		temporaryPath := filepath.Join(directory, temporaryName)
		movedPath := filepath.Join(directory, "moved-original-temp")
		if err := os.Rename(temporaryPath, movedPath); err != nil {
			t.Fatalf("move original temporary: %v", err)
		}
		writeTestFile(t, temporaryPath, "sentinel-content")
		return FinalTargetAbsent, primaryErr
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	if result.Committed || !errors.Is(err, primaryErr) || !errors.Is(err, ErrAtomicTempCleanupRefused) {
		t.Fatalf("result/error = %+v/%v, want original and cleanup-refused errors", result, err)
	}
	assertFileContent(t, target, "old-content")
	assertFileContent(t, filepath.Join(directory, temporaryName), "sentinel-content")
	assertFileContent(t, filepath.Join(directory, "moved-original-temp"), "new-content")
}

func TestAnchoredAtomicReplace_RetainsOriginalTemporaryAfterFailure(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	openFile := operations.openFile
	var temporaryName string
	operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
		temporaryName = name
		return openFile(root, name, flag, mode)
	}
	primaryErr := errors.New("injected write failure")
	operations.writeFile = func(*os.File, []byte) error { return primaryErr }
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	if result.Committed || !errors.Is(err, primaryErr) || !errors.Is(err, ErrAtomicTempCleanupRefused) {
		t.Fatalf("result/error = %+v/%v, want original and cleanup-refused errors", result, err)
	}
	assertFileContent(t, target, "old-content")
	if _, statErr := os.Stat(filepath.Join(directory, temporaryName)); statErr != nil {
		t.Fatalf("retained temporary stat error = %v", statErr)
	}
}

func TestPendingAtomicReplace_CloseRefusesCleanupAfterTemporaryNameReplacement(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	if _, err := pending.Write([]byte("pending-content")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := pending.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	temporaryPath := filepath.Join(directory, pending.name)
	movedPath := filepath.Join(directory, "moved-pending-temp")
	if err := os.Rename(temporaryPath, movedPath); err != nil {
		t.Fatalf("move original temporary: %v", err)
	}
	writeTestFile(t, temporaryPath, "sentinel-content")

	// When
	closeErr := pending.Close()

	// Then
	if !errors.Is(closeErr, ErrAtomicTempCleanupRefused) {
		t.Fatalf("Close() error = %v, want cleanup-refused", closeErr)
	}
	assertFileContent(t, temporaryPath, "sentinel-content")
	assertFileContent(t, movedPath, "pending-content")
}
