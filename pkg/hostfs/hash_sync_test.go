package hostfs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredHash_UsesOneNativeNoFollowRegularHandle(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	writeTestFile(t, target, "anchored-content")
	anchor := newTestAnchor(t, target)
	operations := anchor.finalOperations
	open := operations.open
	regularOpens := 0
	operations.open = func(request finalOpenRequest) (finalOpenResult, error) {
		if request.intent == finalOpenRegular {
			regularOpens++
		}
		return open(request)
	}
	anchor.finalOperations = operations
	wantBytes := sha256.Sum256([]byte("anchored-content"))
	want := hex.EncodeToString(wantBytes[:])

	// When
	got, err := anchor.SHA256()

	// Then
	if err != nil {
		t.Fatalf("SHA256(): %v", err)
	}
	if got != want || regularOpens != 1 {
		t.Fatalf("SHA256/open count = %q/%d, want %q/1", got, regularOpens, want)
	}
}

func TestAnchoredDirectorySync_UsesRetainedNativeDirectory(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	called := 0
	operations.syncDirectory = func(directory *os.File) error {
		called++
		if directory != anchor.NativeDirectory() {
			t.Fatalf("sync directory = %p, want retained native handle %p", directory, anchor.NativeDirectory())
		}
		return nil
	}
	anchor.atomicOperations = operations

	// When
	err := anchor.SyncDirectory()

	// Then
	if err != nil || called != 1 {
		t.Fatalf("SyncDirectory() = %v, calls = %d, want nil/1", err, called)
	}
}

func TestAnchoredDirectorySync_WrapsUnsupportedSemantics(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	anchor := newTestAnchor(t, target)
	operations := anchor.atomicOperations
	unsupported := &DirectorySyncUnsupportedError{Platform: "test"}
	operations.syncDirectory = func(*os.File) error { return unsupported }
	anchor.atomicOperations = operations

	// When
	err := anchor.SyncDirectory()

	// Then
	if !errors.Is(err, ErrDirectorySyncUnsupported) {
		t.Fatalf("SyncDirectory() error = %v, want typed unsupported semantics", err)
	}
}
