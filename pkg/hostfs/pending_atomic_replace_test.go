package hostfs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestAnchoredIfMatch_RevalidatesTypeAndHashImmediatelyBeforeRename(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	t.Cleanup(func() { _ = pending.Close() })
	if _, err := pending.Write([]byte("new-content")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := pending.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	wantBytes := sha256.Sum256([]byte("old-content"))
	want := hex.EncodeToString(wantBytes[:])
	events := make([]string, 0, 4)
	finalOperations := anchor.finalOperations
	open := finalOperations.open
	finalOperations.open = func(request finalOpenRequest) (finalOpenResult, error) {
		switch request.intent {
		case finalOpenClassify:
			events = append(events, "type")
		case finalOpenRegular:
			events = append(events, "hash")
		}
		return open(request)
	}
	anchor.finalOperations = finalOperations
	atomicOperations := anchor.atomicOperations
	rename := atomicOperations.rename
	atomicOperations.rename = func(root *os.Root, oldName, newName string) error {
		events = append(events, "rename")
		return rename(root, oldName, newName)
	}
	atomicOperations.syncDirectory = func(*os.File) error {
		events = append(events, "directory-sync")
		return nil
	}
	anchor.atomicOperations = atomicOperations

	// When
	result, commitErr := pending.CommitIfMatch(want)

	// Then
	if commitErr != nil || !result.Committed {
		t.Fatalf("CommitIfMatch() = %+v/%v, want committed", result, commitErr)
	}
	wantEvents := []string{"type", "hash", "rename", "directory-sync"}
	if !slices.Equal(events, wantEvents) {
		t.Fatalf("events = %v, want %v", events, wantEvents)
	}
}

func TestAnchoredIfMatch_TargetChangedBeforeCommitPreservesChangedTarget(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	t.Cleanup(func() { _ = pending.Close() })
	if _, err := pending.Write([]byte("new-content")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := pending.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	wantBytes := sha256.Sum256([]byte("old-content"))
	if err := os.WriteFile(target, []byte("changed-content"), 0o600); err != nil {
		t.Fatalf("change target: %v", err)
	}

	// When
	result, commitErr := pending.CommitIfMatch(hex.EncodeToString(wantBytes[:]))

	// Then
	if result.Committed || !errors.Is(commitErr, ErrIfMatchSHA256Mismatch) {
		t.Fatalf("CommitIfMatch() = %+v/%v, want uncommitted mismatch", result, commitErr)
	}
	assertFileContent(t, target, "changed-content")
}

func TestAnchoredIfMatch_SpecialTargetAbortsBeforeRename(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	writeTestFile(t, target, "old-content")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	t.Cleanup(func() { _ = pending.Close() })
	if _, err := pending.Write([]byte("new-content")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := pending.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatalf("remove target: %v", err)
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("replace target with directory: %v", err)
	}

	// When
	result, commitErr := pending.CommitIfMatch("")

	// Then
	var typeErr *FinalTargetTypeError
	if result.Committed || !errors.As(commitErr, &typeErr) || typeErr.Actual != FinalTargetDirectory {
		t.Fatalf("CommitIfMatch() = %+v/%v, want directory type rejection", result, commitErr)
	}
	if info, statErr := os.Stat(target); statErr != nil || !info.IsDir() {
		t.Fatalf("special target changed after rejection: %v/%v", info, statErr)
	}
}

func TestAnchoredIfMatch_RequiresSealedTemporaryBeforeCommit(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	t.Cleanup(func() { _ = pending.Close() })

	// When
	result, commitErr := pending.CommitIfMatch("")

	// Then
	if result.Committed || !errors.Is(commitErr, ErrAtomicTempNotSealed) {
		t.Fatalf("CommitIfMatch() = %+v/%v, want uncommitted not-sealed error", result, commitErr)
	}
}

func TestAnchoredIfMatch_CloseRefusesTemporaryCleanupAfterMismatch(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	writeTestFile(t, target, "current-content")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	if _, err := pending.Write([]byte("new-content")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := pending.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	// When
	result, commitErr := pending.CommitIfMatch(strings.Repeat("0", sha256.Size*2))
	closeErr := pending.Close()

	// Then
	if result.Committed || !errors.Is(commitErr, ErrIfMatchSHA256Mismatch) || !errors.Is(closeErr, ErrAtomicTempCleanupRefused) {
		t.Fatalf("commit/close = %+v/%v/%v, want mismatch and cleanup refusal", result, commitErr, closeErr)
	}
	if _, statErr := os.Stat(filepath.Join(directory, pending.name)); statErr != nil {
		t.Fatalf("retained temporary stat error = %v", statErr)
	}
}

func TestAnchoredIfMatch_CloseAfterCommitPreservesReplacement(t *testing.T) {
	t.Parallel()

	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	if _, err := pending.Write([]byte("new-content")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := pending.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}
	result, commitErr := pending.CommitIfMatch("")
	if commitErr != nil || !result.Committed {
		t.Fatalf("CommitIfMatch() = %+v/%v, want committed", result, commitErr)
	}

	// When
	closeErr := pending.Close()

	// Then
	assertDefaultAtomicReplaceResult(t, result, commitErr)
	if closeErr != nil {
		t.Fatalf("Close(): %v", closeErr)
	}
	assertFileContent(t, target, "new-content")
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}

func TestAnchoredIfMatch_MissingTargetPreservesErrorText(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	anchor := newTestAnchor(t, target)
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	t.Cleanup(func() { _ = pending.Close() })
	if _, err := pending.Write([]byte("new-content")); err != nil {
		t.Fatalf("Write(): %v", err)
	}
	if err := pending.Seal(); err != nil {
		t.Fatalf("Seal(): %v", err)
	}

	// When
	result, commitErr := pending.CommitIfMatch(strings.Repeat("0", sha256.Size*2))

	// Then
	if result.Committed || !errors.Is(commitErr, ErrIfMatchSHA256Missing) {
		t.Fatalf("CommitIfMatch() = %+v/%v, want missing-target precondition", result, commitErr)
	}
	if commitErr.Error() != "if_match precondition failed: file does not exist" {
		t.Fatalf("error text = %q, want existing handler text", commitErr)
	}
}
