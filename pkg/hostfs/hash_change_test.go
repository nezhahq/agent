package hostfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestAnchoredHash_DetectsTruncationAfterFirstChunk(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "target.txt")
	writeTestFile(t, target, "abcdefgh")
	anchor := newTestAnchor(t, target)
	regularOpens := installHashMutationAfterFirstRead(t, anchor, target, func(file *os.File) error { return file.Truncate(3) })
	digest, err := anchor.SHA256()
	assertFileChangedDuringHash(t, digest, err, expectedHashChange{reason: FileChangeSize, initialSize: 8, finalSize: 3, bytesRead: 4})
	if *regularOpens != 1 {
		t.Fatalf("regular opens = %d, want 1", *regularOpens)
	}
}

func TestAnchoredHash_DetectsExtensionAfterFirstChunk(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "target.txt")
	writeTestFile(t, target, "abcdefgh")
	anchor := newTestAnchor(t, target)
	regularOpens := installHashMutationAfterFirstRead(t, anchor, target, func(file *os.File) error {
		_, err := file.WriteAt([]byte("ijkl"), 8)
		return err
	})
	digest, err := anchor.SHA256()
	assertFileChangedDuringHash(t, digest, err, expectedHashChange{reason: FileChangeSize, initialSize: 8, finalSize: 12, bytesRead: 12})
	if *regularOpens != 1 {
		t.Fatalf("regular opens = %d, want 1", *regularOpens)
	}
}

func TestAnchoredHash_DetectsSameSizeOverwriteWithVisibleModTime(t *testing.T) {
	t.Parallel()
	target := filepath.Join(t.TempDir(), "target.txt")
	writeTestFile(t, target, "abcdefgh")
	anchor := newTestAnchor(t, target)
	changedTime := time.Unix(1_700_000_000, 123_000_000)
	regularOpens := installHashMutationAfterFirstRead(t, anchor, target, func(file *os.File) error {
		if _, err := file.WriteAt([]byte("WXYZ"), 4); err != nil {
			return err
		}
		return os.Chtimes(target, changedTime, changedTime)
	})
	digest, err := anchor.SHA256()
	assertFileChangedDuringHash(t, digest, err, expectedHashChange{reason: FileChangeModificationTime, initialSize: 8, finalSize: 8, bytesRead: 8})
	if *regularOpens != 1 {
		t.Fatalf("regular opens = %d, want 1", *regularOpens)
	}
}

func TestAnchoredHash_ObservableMetadataDecisionAcceptsIdenticalSnapshot(t *testing.T) {
	t.Parallel()
	file, initial, final := hashDecisionFixture(t)
	reasons := observableHashChangeReasons(initial, final, initial.Size(), os.SameFile)
	if len(reasons) != 0 {
		t.Fatalf("reasons = %v, want none for identical observable metadata", reasons)
	}
	_ = file
}

func TestAnchoredHash_ObservableMetadataDecisionDetectsIdentityChange(t *testing.T) {
	t.Parallel()
	_, initial, final := hashDecisionFixture(t)
	reasons := observableHashChangeReasons(initial, final, initial.Size(), func(os.FileInfo, os.FileInfo) bool { return false })
	if !slices.Contains(reasons, FileChangeIdentity) {
		t.Fatalf("reasons = %v, want identity", reasons)
	}
}

func TestAnchoredHash_PropagatesStatErrors(t *testing.T) {
	t.Parallel()
	for _, failureCall := range []int{1, 2} {
		t.Run(time.Duration(failureCall).String(), func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "target.txt")
			writeTestFile(t, target, "abcdefgh")
			anchor := newTestAnchor(t, target)
			operations := anchor.hashOperations
			stat := operations.stat
			statCalls := 0
			statErr := errors.New("injected stat failure")
			operations.stat = func(file *os.File) (os.FileInfo, error) {
				statCalls++
				if statCalls == failureCall {
					return nil, statErr
				}
				return stat(file)
			}
			anchor.hashOperations = operations
			digest, err := anchor.SHA256()
			if digest != "" || !errors.Is(err, statErr) {
				t.Fatalf("SHA256() = %q/%v, want empty digest and stat error", digest, err)
			}
		})
	}
}

func installHashMutationAfterFirstRead(t *testing.T, anchor *Anchor, target string, mutate func(*os.File) error) *int {
	t.Helper()
	finalOperations := anchor.finalOperations
	open := finalOperations.open
	regularOpens := 0
	finalOperations.open = func(request finalOpenRequest) (finalOpenResult, error) {
		if request.intent == finalOpenRegular {
			regularOpens++
		}
		return open(request)
	}
	anchor.finalOperations = finalOperations
	operations := anchor.hashOperations
	operations.copy = func(destination io.Writer, source *os.File) (int64, error) {
		first := make([]byte, 4)
		read, err := source.Read(first)
		if read != 0 {
			if _, writeErr := destination.Write(first[:read]); writeErr != nil {
				return int64(read), writeErr
			}
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return int64(read), err
		}
		mutationHandle, openErr := os.OpenFile(target, os.O_RDWR, 0)
		if openErr != nil {
			return int64(read), openErr
		}
		mutationErr := mutate(mutationHandle)
		closeErr := mutationHandle.Close()
		if mutationErr != nil || closeErr != nil {
			return int64(read), errors.Join(mutationErr, closeErr)
		}
		remaining, copyErr := io.Copy(destination, source)
		return int64(read) + remaining, copyErr
	}
	anchor.hashOperations = operations
	return &regularOpens
}

func hashDecisionFixture(t *testing.T) (*os.File, os.FileInfo, os.FileInfo) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "target.txt")
	writeTestFile(t, target, "abcdefgh")
	file, err := os.Open(target)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	initial, err := file.Stat()
	if err != nil {
		t.Fatalf("initial Stat(): %v", err)
	}
	final, err := file.Stat()
	if err != nil {
		t.Fatalf("final Stat(): %v", err)
	}
	return file, initial, final
}

type expectedHashChange struct {
	reason      FileChangeReason
	initialSize int64
	finalSize   int64
	bytesRead   int64
}

func assertFileChangedDuringHash(t *testing.T, digest string, err error, want expectedHashChange) {
	t.Helper()
	if digest != "" || !errors.Is(err, ErrFileChangedDuringHash) {
		t.Fatalf("SHA256() = %q/%v, want empty digest and ErrFileChangedDuringHash", digest, err)
	}
	var changed *FileChangedDuringHashError
	if !errors.As(err, &changed) {
		t.Fatalf("SHA256() error = %T, want *FileChangedDuringHashError", err)
	}
	if changed.InitialSize != want.initialSize || changed.FinalSize != want.finalSize || changed.BytesRead != want.bytesRead {
		t.Fatalf("change sizes/read = %d/%d/%d, want %d/%d/%d", changed.InitialSize, changed.FinalSize, changed.BytesRead, want.initialSize, want.finalSize, want.bytesRead)
	}
	if !slices.Contains(changed.Reasons, want.reason) {
		t.Fatalf("change reasons = %v, want %v", changed.Reasons, want.reason)
	}
	if changed.InitialModTime.IsZero() || changed.FinalModTime.IsZero() {
		t.Fatalf("change times = %v/%v, want observable times", changed.InitialModTime, changed.FinalModTime)
	}
}
