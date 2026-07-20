package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchoredAtomicReplace_Absent(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "created.txt")
	anchor := newTestAnchor(t, target)

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o640)

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
	assertFileContent(t, target, "new-content")
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatalf("stat target: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("target mode = %o, want 640", got)
	}
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}

func TestAnchoredAtomicReplace_Existing(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "existing.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
	assertFileContent(t, target, "new-content")
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}

func TestAnchoredAtomicReplace_PostRenameSyncReportsCommitted(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "durability.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	syncErr := errors.New("injected parent sync failure")
	operations := anchor.atomicOperations
	operations.syncDirectory = func(*os.File) error { return syncErr }
	anchor.atomicOperations = operations

	// When
	result, err := anchor.AtomicReplace([]byte("committed-content"), 0o600)

	// Then
	if !result.Committed || result.Durability != DurabilityUnknown {
		t.Fatalf("result = %+v, want committed with unknown durability", result)
	}
	if !errors.Is(err, ErrCommittedDurabilityUnknown) || !errors.Is(err, syncErr) {
		t.Fatalf("AtomicReplace() error = %v, want committed durability unknown wrapping sync failure", err)
	}
	var durabilityErr *CommittedDurabilityUnknown
	if !errors.As(err, &durabilityErr) || durabilityErr.Path != target {
		t.Fatalf("AtomicReplace() error = %T %#v, want path %q", err, err, target)
	}
	assertFileContent(t, target, "committed-content")
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}

func TestAnchoredAtomicReplace_UsesPrivateUnpredictableSameDirectoryTemps(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "private.txt")
	anchor := newTestAnchor(t, target)
	seenNames := make(map[string]struct{})
	operations := anchor.atomicOperations
	defaultOpen := operations.openFile
	operations.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
		if filepath.Base(name) != name || !strings.HasPrefix(name, atomicTempPrefix()) {
			t.Fatalf("temp name = %q, want same-directory private prefix", name)
		}
		if flag&os.O_CREATE == 0 || flag&os.O_EXCL == 0 || flag&os.O_TRUNC != 0 {
			t.Fatalf("temp flags = %#x, want O_CREATE|O_EXCL without O_TRUNC", flag)
		}
		if mode != 0o600 {
			t.Fatalf("temp creation mode = %o, want private 600", mode)
		}
		if _, duplicate := seenNames[name]; duplicate {
			t.Fatalf("temp name %q was reused", name)
		}
		seenNames[name] = struct{}{}
		return defaultOpen(root, name, flag, mode)
	}
	anchor.atomicOperations = operations

	// When / Then
	for index := range 16 {
		content := []byte{byte(index)}
		result, err := anchor.AtomicReplace(content, 0o600)
		assertDefaultAtomicReplaceResult(t, result, err)
	}
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}

func TestAnchoredAtomicReplace_RejectsUnsupportedModeBeforeMutation(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "mode.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)

	// When
	result, err := anchor.AtomicReplace([]byte("new-content"), os.ModeSetuid|0o600)

	// Then
	if result.Committed || !errors.Is(err, ErrUnsupportedFileMode) {
		t.Fatalf("result/error = %+v/%v, want uncommitted unsupported mode", result, err)
	}
	assertFileContent(t, target, "old-content")
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	if got := string(content); got != want {
		t.Fatalf("content = %q, want %q", got, want)
	}
}

func assertNoAtomicTempEntries(t *testing.T, directory, base string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read temp directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), atomicTempPrefix()) {
			t.Fatalf("temporary entry %q remained", entry.Name())
		}
	}
}
