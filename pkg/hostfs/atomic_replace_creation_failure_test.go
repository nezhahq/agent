package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredAtomicReplace_TempCreationFailuresPreserveOld(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject func(*atomicReplaceOperations, error)
	}{
		{
			name: "random name",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.temporaryName = func() (string, error) { return "", injected }
			},
		},
		{
			name: "non-exist create error",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.openFile = func(*os.Root, string, int, os.FileMode) (*os.File, error) {
					return nil, injected
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			directory := t.TempDir()
			target := filepath.Join(directory, "target.txt")
			writeTestFile(t, target, "old-content")
			anchor := newTestAnchor(t, target)
			injected := errors.New("injected " + test.name + " failure")
			operations := anchor.atomicOperations
			test.inject(&operations, injected)
			anchor.atomicOperations = operations

			// When
			result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

			// Then
			if result.Committed || !errors.Is(err, injected) {
				t.Fatalf("result/error = %+v/%v, want uncommitted injected error", result, err)
			}
			var pathErr *PathError
			if !errors.As(err, &pathErr) || pathErr.Path != target {
				t.Fatalf("AtomicReplace() error = %T %#v, want PathError for %q", err, err, target)
			}
			assertFileContent(t, target, "old-content")
			assertNoAtomicTempEntries(t, directory, filepath.Base(target))
		})
	}
}

func TestAnchoredAtomicReplace_TempCollisionExhaustionIsTyped(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	nameCalls := 0
	openCalls := 0
	operations.temporaryName = func() (string, error) {
		nameCalls++
		return atomicTempPrefix() + "collision", nil
	}
	operations.openFile = func(*os.Root, string, int, os.FileMode) (*os.File, error) {
		openCalls++
		return nil, os.ErrExist
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	if result.Committed || !errors.Is(err, os.ErrExist) || !errors.Is(err, ErrAtomicTempCollisionExhausted) {
		t.Fatalf("result/error = %+v/%v, want uncommitted collision exhaustion", result, err)
	}
	var collisionErr *AtomicTempCollisionExhaustedError
	if !errors.As(err, &collisionErr) || collisionErr.Attempts != maxAtomicTempAttempts {
		t.Fatalf("AtomicReplace() error = %T %#v, want %d-attempt collision error", err, err, maxAtomicTempAttempts)
	}
	if nameCalls != maxAtomicTempAttempts || openCalls != maxAtomicTempAttempts {
		t.Fatalf("name/open calls = %d/%d, want %d/%d", nameCalls, openCalls, maxAtomicTempAttempts, maxAtomicTempAttempts)
	}
	assertFileContent(t, target, "old-content")
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}
