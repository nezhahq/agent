package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredAtomicReplace_RetainsTempCloseOwnershipAfterCloseFailure(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	openFile := operations.openFile
	closeErr := errors.New("injected close failure")
	closeFileCalls := 0
	closeTempCalls := 0
	calls := make([]string, 0, 2)
	var temporaryName string
	var temporaryFile *os.File
	operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
		temporaryName = name
		file, err := openFile(root, name, flag, mode)
		temporaryFile = file
		return file, err
	}
	operations.closeFile = func(*os.File) error {
		closeFileCalls++
		return closeErr
	}
	operations.closeTemp = func(file *os.File) error {
		closeTempCalls++
		calls = append(calls, "closeTemp")
		return file.Close()
	}
	operations.cleanupTemp = func() error {
		calls = append(calls, "cleanupTemp")
		return ErrAtomicTempCleanupRefused
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	if !errors.Is(err, closeErr) {
		t.Fatalf("AtomicReplace() error = %v, want errors.Is(%v)", err, closeErr)
	}
	if result.Committed || result.Durability != DurabilityNotCommitted {
		t.Fatalf("AtomicReplace() result = %+v, want uncommitted and not committed durability", result)
	}
	if closeFileCalls != 1 || closeTempCalls != 1 || len(calls) != 2 || calls[0] != "closeTemp" || calls[1] != "cleanupTemp" {
		t.Fatalf("cleanup calls = closeFile:%d closeTemp:%d order:%v, want one close retry before cleanup refusal", closeFileCalls, closeTempCalls, calls)
	}
	if temporaryFile == nil || !errors.Is(temporaryFile.Close(), os.ErrClosed) {
		t.Fatal("temporary descriptor was not closed by cleanup retry")
	}
	if !errors.Is(err, ErrAtomicTempCleanupRefused) {
		t.Fatalf("AtomicReplace() error = %v, want cleanup refusal", err)
	}
	assertFileContent(t, target, "old-content")
	temporaryPath := filepath.Join(directory, temporaryName)
	if _, statErr := os.Lstat(temporaryPath); statErr != nil {
		t.Fatalf("temporary stat error = %v, want retained temporary", statErr)
	}
}
