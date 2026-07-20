//go:build unix

package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAnchoredAtomicReplace_ParentReplaced(t *testing.T) {
	// Given
	root := t.TempDir()
	parentPath := filepath.Join(root, "parent")
	retainedPath := filepath.Join(root, "retained-parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	target := filepath.Join(parentPath, "target.txt")
	writeTestFile(t, target, "old-A")
	anchor := newTestAnchor(t, target)
	if err := os.Rename(parentPath, retainedPath); err != nil {
		t.Fatalf("rename retained parent: %v", err)
	}
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatalf("mkdir replacement parent: %v", err)
	}
	writeTestFile(t, filepath.Join(parentPath, "target.txt"), "sentinel-B")

	// When
	result, err := anchor.AtomicReplace([]byte("new-A"), 0o600)

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
	assertFileContent(t, filepath.Join(retainedPath, "target.txt"), "new-A")
	assertFileContent(t, filepath.Join(parentPath, "target.txt"), "sentinel-B")
}

func TestAnchoredAtomicReplace_RejectsTargetChangedBeforeRename(t *testing.T) {
	tests := []struct {
		name       string
		wantType   FinalTargetType
		changeLeaf func(*testing.T, string, string)
		verify     func(*testing.T, string, string)
	}{
		{
			name:     "symlink",
			wantType: FinalTargetSymlinkReparse,
			changeLeaf: func(t *testing.T, target, sentinel string) {
				writeTestFile(t, sentinel, "sentinel")
				if err := os.Symlink(sentinel, target); err != nil {
					t.Fatalf("symlink target: %v", err)
				}
			},
			verify: func(t *testing.T, target, sentinel string) {
				assertFileContent(t, sentinel, "sentinel")
				if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("target mode/error = %v/%v, want symlink", info, err)
				}
			},
		},
		{
			name:     "FIFO",
			wantType: FinalTargetFIFO,
			changeLeaf: func(t *testing.T, target, _ string) {
				if err := unix.Mkfifo(target, 0o600); err != nil {
					t.Fatalf("mkfifo target: %v", err)
				}
			},
			verify: func(t *testing.T, target, _ string) {
				if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
					t.Fatalf("target mode/error = %v/%v, want FIFO", info, err)
				}
			},
		},
		{
			name:     "directory",
			wantType: FinalTargetDirectory,
			changeLeaf: func(t *testing.T, target, _ string) {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatalf("mkdir target: %v", err)
				}
				writeTestFile(t, filepath.Join(target, "sentinel"), "directory-sentinel")
			},
			verify: func(t *testing.T, target, _ string) {
				assertFileContent(t, filepath.Join(target, "sentinel"), "directory-sentinel")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			directory := t.TempDir()
			target := filepath.Join(directory, "target")
			sentinel := filepath.Join(directory, "sentinel")
			writeTestFile(t, target, "old-content")
			anchor := newTestAnchor(t, target)
			nativeOpenCalls := 0
			openFinal := anchor.finalOperations.open
			anchor.finalOperations.open = func(request finalOpenRequest) (finalOpenResult, error) {
				nativeOpenCalls++
				return openFinal(request)
			}
			operations := anchor.atomicOperations
			openFile := operations.openFile
			var temporaryName string
			operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
				temporaryName = name
				return openFile(root, name, flag, mode)
			}
			revalidate := operations.revalidateFinal
			operations.revalidateFinal = func(anchor *Anchor) (FinalTargetType, error) {
				if err := os.Remove(target); err != nil {
					return FinalTargetAbsent, err
				}
				test.changeLeaf(t, target, sentinel)
				return revalidate(anchor)
			}
			anchor.atomicOperations = operations

			// When
			result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

			// Then
			if result.Committed {
				t.Fatalf("result = %+v, want not committed", result)
			}
			var typeErr *FinalTargetTypeError
			if !errors.As(err, &typeErr) || typeErr.Actual != test.wantType || !errors.Is(err, ErrAtomicTempCleanupRefused) {
				t.Fatalf("AtomicReplace() error = %T %v, want actual type %v", err, err, test.wantType)
			}
			if nativeOpenCalls == 0 {
				t.Fatal("native no-follow revalidation was not called")
			}
			test.verify(t, target, sentinel)
			if _, statErr := os.Stat(filepath.Join(directory, temporaryName)); statErr != nil {
				t.Fatalf("retained temporary stat error = %v", statErr)
			}
		})
	}
}

func TestAnchoredAtomicReplace_CompetingRegularIsReplacedWithoutCASClaim(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	revalidate := operations.revalidateFinal
	operations.revalidateFinal = func(anchor *Anchor) (FinalTargetType, error) {
		writeTestFile(t, target, "competing-regular")
		return revalidate(anchor)
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
	assertFileContent(t, target, "new-content")
}

func TestAnchoredAtomicReplace_EXDEVDoesNotFallback(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "cross-device.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	openFile := operations.openFile
	var temporaryName string
	operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
		temporaryName = name
		return openFile(root, name, flag, mode)
	}
	renameCalls := 0
	operations.rename = func(*os.Root, string, string) error {
		renameCalls++
		return unix.EXDEV
	}
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	if result.Committed || !errors.Is(err, unix.EXDEV) || !errors.Is(err, ErrAtomicTempCleanupRefused) || renameCalls != 1 {
		t.Fatalf("result/error/rename calls = %+v/%v/%d, want one failed EXDEV commit", result, err, renameCalls)
	}
	assertFileContent(t, target, "old-content")
	if _, statErr := os.Stat(filepath.Join(directory, temporaryName)); statErr != nil {
		t.Fatalf("retained temporary stat error = %v", statErr)
	}
}
