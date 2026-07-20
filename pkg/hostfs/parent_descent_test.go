package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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

func TestAnchoredCreateDirs_CreatesMissingParentComponentsInOrder(t *testing.T) {
	// Given
	ancestor := t.TempDir()
	parent := filepath.Join(ancestor, "first", "second")
	target := filepath.Join(parent, "target.txt")
	anchor := newTestAnchor(t, target)
	if anchor.AncestorPath() != ancestor {
		t.Fatalf("ancestor = %q, want %q", anchor.AncestorPath(), ancestor)
	}
	operations := anchor.descentOperations
	mkdir := operations.mkdir
	var created []string
	operations.mkdir = func(root *os.Root, name string, mode os.FileMode) error {
		created = append(created, name)
		return mkdir(root, name, mode)
	}
	anchor.descentOperations = operations

	// When
	err := anchor.EnsureParent(true, 0o755)

	// Then
	if err != nil {
		t.Fatalf("EnsureParent(): %v", err)
	}
	if want := []string{"first", "second"}; !slices.Equal(created, want) {
		t.Fatalf("created parent components = %v, want %v", created, want)
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
