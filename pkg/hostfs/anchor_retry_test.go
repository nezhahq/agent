package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchor_RetriesMismatchedHandlePairsAndClosesRejectedPairs(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	operations := defaultAnchorOperations()
	var roots []*os.Root
	var nativeDirectories []*os.File
	openRoot := operations.openRoot
	openNativeDirectory := operations.openNativeDirectory
	operations.openRoot = func(path string) (*os.Root, error) {
		root, err := openRoot(path)
		if root != nil {
			roots = append(roots, root)
		}
		return root, err
	}
	operations.openNativeDirectory = func(path string) (*os.File, error) {
		directory, err := openNativeDirectory(path)
		if directory != nil {
			nativeDirectories = append(nativeDirectories, directory)
		}
		return directory, err
	}
	comparisons := 0
	operations.sameFile = func(first os.FileInfo, second os.FileInfo) bool {
		comparisons++
		return comparisons == 2 && os.SameFile(first, second)
	}

	anchor, err := newWithOperations(filepath.Join(directory, "file.txt"), operations)
	if err != nil {
		t.Fatalf("newWithOperations(): %v", err)
	}
	t.Cleanup(func() {
		if err := anchor.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})

	if comparisons != 2 {
		t.Fatalf("SameFile comparisons = %d, want 2", comparisons)
	}
	if _, err := roots[0].Stat("."); err == nil {
		t.Fatal("rejected Root remained open")
	}
	if _, err := nativeDirectories[0].Stat(); err == nil {
		t.Fatal("rejected native directory remained open")
	}
	if _, err := roots[1].Stat("."); err != nil {
		t.Fatalf("accepted Root is closed: %v", err)
	}
	if _, err := nativeDirectories[1].Stat(); err != nil {
		t.Fatalf("accepted native directory is closed: %v", err)
	}
}

func TestAnchor_ReturnsTypedMismatchAfterBoundedRetries(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	operations := defaultAnchorOperations()
	var roots []*os.Root
	var nativeDirectories []*os.File
	openRoot := operations.openRoot
	openNativeDirectory := operations.openNativeDirectory
	operations.openRoot = func(path string) (*os.Root, error) {
		root, err := openRoot(path)
		if root != nil {
			roots = append(roots, root)
		}
		return root, err
	}
	operations.openNativeDirectory = func(path string) (*os.File, error) {
		directory, err := openNativeDirectory(path)
		if directory != nil {
			nativeDirectories = append(nativeDirectories, directory)
		}
		return directory, err
	}
	operations.sameFile = func(os.FileInfo, os.FileInfo) bool { return false }

	anchor, err := newWithOperations(filepath.Join(directory, "file.txt"), operations)

	if anchor != nil {
		t.Fatalf("anchor = %#v, want nil", anchor)
	}
	if !errors.Is(err, ErrHandleMismatch) {
		t.Fatalf("error = %v, want ErrHandleMismatch", err)
	}
	if len(roots) != maxPairAttempts || len(nativeDirectories) != maxPairAttempts {
		t.Fatalf("attempts root/native = %d/%d, want %d/%d", len(roots), len(nativeDirectories), maxPairAttempts, maxPairAttempts)
	}
	for index, root := range roots {
		if _, statErr := root.Stat("."); statErr == nil {
			t.Fatalf("Root attempt %d remained open", index)
		}
	}
	for index, directory := range nativeDirectories {
		if _, statErr := directory.Stat(); statErr == nil {
			t.Fatalf("native attempt %d remained open", index)
		}
	}
}

func TestAnchor_ClosesRootWhenNativeHandleSetupFails(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	operations := defaultAnchorOperations()
	openRoot := operations.openRoot
	var acquiredRoot *os.Root
	operations.openRoot = func(path string) (*os.Root, error) {
		root, err := openRoot(path)
		acquiredRoot = root
		return root, err
	}
	setupErr := errors.New("native setup interrupted")
	operations.openNativeDirectory = func(string) (*os.File, error) {
		return nil, setupErr
	}

	anchor, err := newWithOperations(filepath.Join(directory, "file.txt"), operations)

	if anchor != nil {
		t.Fatalf("anchor = %#v, want nil", anchor)
	}
	if !errors.Is(err, setupErr) {
		t.Fatalf("error = %v, want setup interruption", err)
	}
	if acquiredRoot == nil {
		t.Fatal("test did not acquire a Root")
	}
	if _, statErr := acquiredRoot.Stat("."); statErr == nil {
		t.Fatal("Root remained open after native setup interruption")
	}
}
