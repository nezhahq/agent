package hostfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAnchor_RejectsInvalidTargetPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		target  string
		wantErr error
	}{
		{name: "empty", target: "", wantErr: ErrPathRequired},
		{name: "relative", target: "relative/file", wantErr: ErrAbsolutePathRequired},
		{name: "filesystem root", target: filesystemRoot(t), wantErr: ErrFilesystemRoot},
		{name: "empty final name", target: filepath.Join(t.TempDir(), "directory") + string(filepath.Separator), wantErr: ErrFinalNameRequired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			anchor, err := New(test.target)

			if anchor != nil {
				if closeErr := anchor.Close(); closeErr != nil {
					t.Errorf("close unexpected Anchor: %v", closeErr)
				}
				t.Fatalf("New(%q) anchor = %#v, want nil", test.target, anchor)
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("New(%q) error = %v, want %v", test.target, err, test.wantErr)
			}
			var pathErr *PathError
			if !errors.As(err, &pathErr) {
				t.Fatalf("New(%q) error type = %T, want *PathError", test.target, err)
			}
		})
	}
}

func TestAnchor_StoresCleanTargetParentChainAndFinalName(t *testing.T) {
	t.Parallel()

	existingParent := t.TempDir()
	target := filepath.Join(existingParent, "missing-one", "missing-two", "..", "missing-two", "final.txt")

	anchor, err := New(target)
	if err != nil {
		t.Fatalf("New(%q): %v", target, err)
	}
	t.Cleanup(func() {
		if err := anchor.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})

	if got, want := anchor.TargetPath(), filepath.Clean(target); got != want {
		t.Fatalf("TargetPath() = %q, want %q", got, want)
	}
	if got := anchor.AncestorPath(); got != existingParent {
		t.Fatalf("AncestorPath() = %q, want %q", got, existingParent)
	}
	if got, want := anchor.MissingParents(), []string{"missing-one", "missing-two"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingParents() = %#v, want %#v", got, want)
	}
	if got := anchor.FinalName(); got != "final.txt" {
		t.Fatalf("FinalName() = %q, want final.txt", got)
	}

	rootInfo, err := anchor.Root().Stat(".")
	if err != nil {
		t.Fatalf("Root().Stat(.): %v", err)
	}
	nativeInfo, err := anchor.NativeDirectory().Stat()
	if err != nil {
		t.Fatalf("NativeDirectory().Stat(): %v", err)
	}
	if !os.SameFile(rootInfo, nativeInfo) {
		t.Fatal("Root and native directory handle must reference the same directory")
	}
}

func TestAnchor_FindsRootAsLongestExistingAncestor(t *testing.T) {
	t.Parallel()

	root := filesystemRoot(t)
	missingTop := unusedRootChild(t, root)
	target := filepath.Join(missingTop, "nested", "file.txt")

	anchor, err := New(target)
	if err != nil {
		t.Fatalf("New(%q): %v", target, err)
	}
	t.Cleanup(func() {
		if err := anchor.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})

	if got := anchor.AncestorPath(); got != root {
		t.Fatalf("AncestorPath() = %q, want root %q", got, root)
	}
	if got, want := anchor.MissingParents(), []string{filepath.Base(missingTop), "nested"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("MissingParents() = %#v, want %#v", got, want)
	}
	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatalf("Stat root: %v", err)
	}
	anchoredInfo, err := anchor.Root().Stat(".")
	if err != nil {
		t.Fatalf("Root().Stat(.): %v", err)
	}
	if !os.SameFile(rootInfo, anchoredInfo) {
		t.Fatal("root-only ancestor must anchor the filesystem root")
	}
}

func TestAnchor_CloseIsNilSafeAndIdempotent(t *testing.T) {
	t.Parallel()

	var nilAnchor *Anchor
	if err := nilAnchor.Close(); err != nil {
		t.Fatalf("nil Close() = %v, want nil", err)
	}

	anchor, err := New(filepath.Join(t.TempDir(), "file.txt"))
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	if err := anchor.Close(); err != nil {
		t.Fatalf("first Close(): %v", err)
	}
	if err := anchor.Close(); err != nil {
		t.Fatalf("second Close(): %v", err)
	}
	if _, err := anchor.Root().Stat("."); err == nil {
		t.Fatal("Root().Stat(.) after Close() succeeded, want closed error")
	}
	if _, err := anchor.NativeDirectory().Stat(); err == nil {
		t.Fatal("NativeDirectory().Stat() after Close() succeeded, want closed error")
	}
}

func filesystemRoot(t *testing.T) string {
	t.Helper()

	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	clean := filepath.Clean(root)
	if filepath.Dir(clean) != clean {
		t.Fatalf("derived filesystem root %q is not reflexive", clean)
	}
	return clean
}

func unusedRootChild(t *testing.T, root string) string {
	t.Helper()

	for range 8 {
		var random [12]byte
		if _, err := rand.Read(random[:]); err != nil {
			t.Fatalf("generate root child: %v", err)
		}
		candidate := filepath.Join(root, "hostfs-anchor-"+hex.EncodeToString(random[:]))
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			return candidate
		}
	}
	t.Fatal("could not find an unused filesystem-root child")
	return ""
}
