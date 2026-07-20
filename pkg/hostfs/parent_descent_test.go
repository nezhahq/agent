package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredCreateDirs_RequiresImmediateParentWhenDisabled(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "missing", "target.txt")
	anchor := newTestAnchor(t, target)

	// When
	err := anchor.EnsureParent(false, 0o755)

	// Then
	if !errors.Is(err, ErrImmediateParentMissing) {
		t.Fatalf("EnsureParent() error = %v, want ErrImmediateParentMissing", err)
	}
	if _, statErr := os.Stat(filepath.Dir(target)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing parent stat error = %v, want not exist", statErr)
	}
}

func TestAnchoredCreateDirs_WalksRootOnlyAncestorChain(t *testing.T) {
	// Given
	reservedPath, err := os.MkdirTemp(string(filepath.Separator), "hostfs-root-chain-")
	if err != nil {
		t.Fatalf("reserve root component: %v", err)
	}
	if err := os.Remove(reservedPath); err != nil {
		t.Fatalf("remove reserved root component: %v", err)
	}
	parent := filepath.Join(reservedPath, "nested")
	target := filepath.Join(parent, "target.txt")
	t.Cleanup(func() { _ = os.RemoveAll(reservedPath) })
	anchor := newTestAnchor(t, target)
	if anchor.AncestorPath() != string(filepath.Separator) {
		t.Fatalf("ancestor = %q, want filesystem root", anchor.AncestorPath())
	}

	// When
	err = anchor.EnsureParent(true, 0o755)

	// Then
	if err != nil {
		t.Fatalf("EnsureParent(): %v", err)
	}
	if len(anchor.MissingParents()) != 0 {
		t.Fatalf("missing parents = %v, want none", anchor.MissingParents())
	}
	if anchor.AncestorPath() != parent {
		t.Fatalf("ancestor = %q, want %q", anchor.AncestorPath(), parent)
	}
	if info, statErr := anchor.Root().Stat("."); statErr != nil || !info.IsDir() {
		t.Fatalf("final Root stat = %v/%v, want directory", info, statErr)
	}
}

func TestAnchoredCreateDirs_ParentPathReplacementCannotRedirect(t *testing.T) {
	// Given
	base := t.TempDir()
	originalParent := filepath.Join(base, "parent")
	if err := os.Mkdir(originalParent, 0o755); err != nil {
		t.Fatalf("mkdir original parent: %v", err)
	}
	target := filepath.Join(originalParent, "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	movedParent := filepath.Join(base, "moved")
	if err := os.Rename(originalParent, movedParent); err != nil {
		t.Fatalf("rename anchored parent: %v", err)
	}
	if err := os.Mkdir(originalParent, 0o755); err != nil {
		t.Fatalf("mkdir replacement parent: %v", err)
	}

	// When
	err := anchor.EnsureParent(true, 0o755)

	// Then
	if err != nil {
		t.Fatalf("EnsureParent(): %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(movedParent, "missing")); statErr != nil {
		t.Fatalf("anchored child missing from original directory: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(originalParent, "missing")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("replacement pathname was mutated: %v", statErr)
	}
}

func TestAnchoredCreateDirs_RejectsSameFileMismatchAndClosesChildPair(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	oldRoot := anchor.Root()
	oldNative := anchor.NativeDirectory()
	operations := anchor.descentOperations
	openRoot := operations.openRoot
	openNative := operations.openNativeDirectory
	var childRoot *os.Root
	var childNative *os.File
	operations.openRoot = func(root *os.Root, name string) (*os.Root, error) {
		opened, err := openRoot(root, name)
		childRoot = opened
		return opened, err
	}
	operations.openNativeDirectory = func(parent *os.File, name string) (*os.File, error) {
		opened, err := openNative(parent, name)
		childNative = opened
		return opened, err
	}
	operations.sameFile = func(os.FileInfo, os.FileInfo) bool { return false }
	anchor.descentOperations = operations

	// When
	err := anchor.EnsureParent(true, 0o755)

	// Then
	if !errors.Is(err, ErrHandleMismatch) {
		t.Fatalf("EnsureParent() error = %v, want ErrHandleMismatch", err)
	}
	if childRoot == nil || childNative == nil {
		t.Fatal("test did not acquire a child pair")
	}
	if _, statErr := childRoot.Stat("."); statErr == nil {
		t.Fatal("mismatched child Root remained open")
	}
	if _, statErr := childNative.Stat(); statErr == nil {
		t.Fatal("mismatched child native directory remained open")
	}
	if _, statErr := oldRoot.Stat("."); statErr != nil {
		t.Fatalf("previous Root closed before child pair was ready: %v", statErr)
	}
	if _, statErr := oldNative.Stat(); statErr != nil {
		t.Fatalf("previous native directory closed before child pair was ready: %v", statErr)
	}
}

func TestAnchoredCreateDirs_ClosesPreviousPairAfterDescent(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	oldRoot := anchor.Root()
	oldNative := anchor.NativeDirectory()

	// When
	err := anchor.EnsureParent(true, 0o755)

	// Then
	if err != nil {
		t.Fatalf("EnsureParent(): %v", err)
	}
	if _, statErr := oldRoot.Stat("."); statErr == nil {
		t.Fatal("previous Root remained open after successful descent")
	}
	if _, statErr := oldNative.Stat(); statErr == nil {
		t.Fatal("previous native directory remained open after successful descent")
	}
	if _, statErr := anchor.Root().Stat("."); statErr != nil {
		t.Fatalf("final Root is closed: %v", statErr)
	}
	if _, statErr := anchor.NativeDirectory().Stat(); statErr != nil {
		t.Fatalf("final native directory is closed: %v", statErr)
	}
	finalRoot := anchor.Root()
	finalNative := anchor.NativeDirectory()
	if err := anchor.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if _, statErr := finalRoot.Stat("."); statErr == nil {
		t.Fatal("final Root remained open after Anchor.Close")
	}
	if _, statErr := finalNative.Stat(); statErr == nil {
		t.Fatal("final native directory remained open after Anchor.Close")
	}
}
