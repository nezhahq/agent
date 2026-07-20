//go:build (unix && !aix) || windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nezhahq/agent/pkg/hostfs"
)

func TestAnchor_PreservesAbsolutePathContractAndRootGuard(t *testing.T) {
	t.Parallel()

	for _, target := range hostAbsolutePaths() {
		clean, err := resolveFsPath(target)
		if err != nil {
			t.Fatalf("resolveFsPath(%q): %v", target, err)
		}
		if isFilesystemRoot(clean) {
			t.Fatalf("hostAbsolutePaths contains root target %q", clean)
		}
	}

	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	anchor, err := hostfs.New(root)
	if anchor != nil {
		if closeErr := anchor.Close(); closeErr != nil {
			t.Errorf("close unexpected root Anchor: %v", closeErr)
		}
		t.Fatalf("hostfs.New(%q) returned an Anchor, want nil", root)
	}
	if !errors.Is(err, hostfs.ErrFilesystemRoot) {
		t.Fatalf("hostfs.New(%q) error = %v, want ErrFilesystemRoot", root, err)
	}
}

func TestAnchor_PathReplacementCannotRedirect(t *testing.T) {
	barrier := make(chan struct{})
	fixture, capabilityErr := newParentReplacementFixture(t, barrier)
	if capabilityErr != nil {
		t.Fatalf("create parent replacement fixture: %v", capabilityErr)
	}

	anchor, err := hostfs.New(filepath.Join(fixture.ParentPath, "future-file"))
	if err != nil {
		t.Fatalf("anchor parent link to A: %v", err)
	}
	t.Cleanup(func() {
		if err := anchor.Close(); err != nil {
			t.Errorf("close Anchor: %v", err)
		}
	})

	close(barrier)
	if err := fixture.waitForReplacement(fixtureCompletionDeadline); err != nil {
		t.Fatalf("replace parent link with B: %v", err)
	}
	pathSentinel, err := fixture.readLinkedSentinel()
	if err != nil {
		t.Fatalf("read replaced pathname sentinel: %v", err)
	}
	if pathSentinel != "B" {
		t.Fatalf("replaced pathname sentinel = %q, want B", pathSentinel)
	}

	anchoredSentinel, err := anchor.Root().ReadFile("sentinel")
	if err != nil {
		t.Fatalf("read anchored sentinel: %v", err)
	}
	if got := string(anchoredSentinel); got != "A" {
		t.Fatalf("anchored sentinel = %q, want A", got)
	}
	directoryAInfo, err := os.Stat(fixture.DirectoryA)
	if err != nil {
		t.Fatalf("stat directory A: %v", err)
	}
	rootInfo, err := anchor.Root().Stat(".")
	if err != nil {
		t.Fatalf("stat Anchor Root: %v", err)
	}
	nativeInfo, err := anchor.NativeDirectory().Stat()
	if err != nil {
		t.Fatalf("stat Anchor native directory: %v", err)
	}
	if !os.SameFile(rootInfo, directoryAInfo) {
		t.Fatal("Anchor Root was redirected away from directory A")
	}
	if !os.SameFile(nativeInfo, directoryAInfo) {
		t.Fatal("Anchor native directory was redirected away from directory A")
	}
}
