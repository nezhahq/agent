package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchoredAtomicReplace_CleanupCallsPreserveErrorsAndOwnership(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		closeErr   error
		cleanupErr error
	}{
		{name: "close fails then cleanup is refused", closeErr: errors.New("injected cleanup close failure")},
		{name: "cleanup refusal is reported", cleanupErr: errors.New("injected cleanup failure")},
		{
			name:       "primary close and cleanup fail",
			closeErr:   errors.New("injected cleanup close failure"),
			cleanupErr: errors.New("injected cleanup failure"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			directory := t.TempDir()
			target := filepath.Join(directory, "target.txt")
			writeTestFile(t, target, "old-content")
			anchor := newTestAnchor(t, target)
			primaryErr := errors.New("injected write failure")
			operations := anchor.atomicOperations
			openFile := operations.openFile
			var temporaryName string
			var temporaryFile *os.File
			operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
				temporaryName = name
				file, err := openFile(root, name, flag, mode)
				temporaryFile = file
				return file, err
			}
			operations.writeFile = func(*os.File, []byte) error { return primaryErr }
			calls := make([]string, 0, 2)
			operations.closeTemp = func(file *os.File) error {
				calls = append(calls, "close")
				return errors.Join(file.Close(), test.closeErr)
			}
			operations.cleanupTemp = func() error {
				calls = append(calls, "cleanup")
				if test.cleanupErr != nil {
					return errors.Join(ErrAtomicTempCleanupRefused, test.cleanupErr)
				}
				return ErrAtomicTempCleanupRefused
			}
			anchor.atomicOperations = operations

			// When
			result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

			// Then
			if result.Committed || err == nil || strings.Join(calls, ",") != "close,cleanup" {
				t.Fatalf("result/error/calls = %+v/%v/%v, want uncommitted close then cleanup refusal", result, err, calls)
			}
			if temporaryFile == nil || !errors.Is(temporaryFile.Close(), os.ErrClosed) {
				t.Fatal("temporary descriptor was not closed exactly once by cleanup")
			}
			for _, expected := range []error{primaryErr, test.closeErr, test.cleanupErr, ErrAtomicTempCleanupRefused} {
				if expected != nil && !errors.Is(err, expected) {
					t.Fatalf("AtomicReplace() error = %v, want errors.Is(%v)", err, expected)
				}
			}
			var pathErr *PathError
			if !errors.As(err, &pathErr) || pathErr.Path != target {
				t.Fatalf("AtomicReplace() error = %T %#v, want PathError for %q", err, err, target)
			}
			assertFileContent(t, target, "old-content")
			temporaryPath := filepath.Join(directory, temporaryName)
			_, statErr := os.Lstat(temporaryPath)
			if statErr != nil {
				t.Fatalf("owned temporary stat: %v", statErr)
			}
		})
	}
}
