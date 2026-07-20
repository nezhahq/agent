package hostfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredAtomicReplace_PreRenameFailurePreservesOld(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		inject func(*atomicReplaceOperations, error)
	}{
		{
			name: "write",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.writeFile = func(*os.File, []byte) error { return injected }
			},
		},
		{
			name: "chmod",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.chmodFile = func(*os.File, os.FileMode) error { return injected }
			},
		},
		{
			name: "file sync",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.syncFile = func(*os.File) error { return injected }
			},
		},
		{
			name: "close",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.closeFile = func(file *os.File) error {
					return errors.Join(file.Close(), injected)
				}
			},
		},
		{
			name: "revalidate",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.revalidateFinal = func(*Anchor) (FinalTargetType, error) {
					return FinalTargetAbsent, injected
				}
			},
		},
		{
			name: "rename",
			inject: func(operations *atomicReplaceOperations, injected error) {
				operations.rename = func(*os.Root, string, string) error { return injected }
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			directory := t.TempDir()
			target := filepath.Join(directory, "preserved.txt")
			writeTestFile(t, target, "old-content")
			anchor := newTestAnchor(t, target)
			injected := errors.New("injected " + test.name + " failure")
			operations := anchor.atomicOperations
			openFile := operations.openFile
			var temporaryName string
			operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
				temporaryName = name
				return openFile(root, name, flag, mode)
			}
			test.inject(&operations, injected)
			anchor.atomicOperations = operations

			// When
			result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

			// Then
			if result.Committed || result.Durability != DurabilityNotCommitted {
				t.Fatalf("result = %+v, want not committed", result)
			}
			if !errors.Is(err, injected) || !errors.Is(err, ErrAtomicTempCleanupRefused) {
				t.Fatalf("AtomicReplace() error = %v, want injected and cleanup-refused errors", err)
			}
			assertFileContent(t, target, "old-content")
			if _, statErr := os.Stat(filepath.Join(directory, temporaryName)); statErr != nil {
				t.Fatalf("retained temporary stat error = %v", statErr)
			}
		})
	}
}

func TestAnchoredAtomicReplace_ShortWritePreservesOld(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "short-write.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	openFile := operations.openFile
	var temporaryName string
	operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
		temporaryName = name
		return openFile(root, name, flag, mode)
	}
	operations.writeFile = func(file *os.File, data []byte) error {
		_, err := file.Write(data[:1])
		return errors.Join(err, io.ErrShortWrite)
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	if result.Committed || !errors.Is(err, io.ErrShortWrite) || !errors.Is(err, ErrAtomicTempCleanupRefused) {
		t.Fatalf("result/error = %+v/%v, want uncommitted short write and cleanup refusal", result, err)
	}
	assertFileContent(t, target, "old-content")
	if _, statErr := os.Stat(filepath.Join(directory, temporaryName)); statErr != nil {
		t.Fatalf("retained temporary stat error = %v", statErr)
	}
}

func TestAnchoredAtomicReplace_MissingImmediateParentDoesNotCreateChain(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "missing", "target.txt")
	anchor := newTestAnchor(t, target)

	// When
	result, err := anchor.AtomicReplace([]byte("content"), 0o600)

	// Then
	if result.Committed || !errors.Is(err, ErrImmediateParentMissing) {
		t.Fatalf("result/error = %+v/%v, want missing immediate parent", result, err)
	}
	if _, statErr := os.Stat(filepath.Dir(target)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing parent stat error = %v, want not exist", statErr)
	}
}
