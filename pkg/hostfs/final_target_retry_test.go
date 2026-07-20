package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAnchoredOpen_retries_changed_final_and_closes_every_rejected_file(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	targetA := filepath.Join(directory, "target-a")
	targetB := filepath.Join(directory, "target-b")
	if err := os.WriteFile(targetA, []byte("A"), 0o600); err != nil {
		t.Fatalf("write target A: %v", err)
	}
	if err := os.WriteFile(targetB, []byte("B"), 0o600); err != nil {
		t.Fatalf("write target B: %v", err)
	}
	anchor := newTestAnchor(t, targetA)
	metadataA, err := os.Lstat(targetA)
	if err != nil {
		t.Fatalf("Lstat target A: %v", err)
	}
	anchor.finalOperations.lstat = func(*os.Root, string) (os.FileInfo, error) {
		return metadataA, nil
	}
	var rejected []*os.File
	anchor.finalOperations.open = func(finalOpenRequest) (finalOpenResult, error) {
		file, err := os.Open(targetB)
		if err != nil {
			return finalOpenResult{}, err
		}
		rejected = append(rejected, file)
		return finalOpenResult{file: file, targetType: FinalTargetRegular}, nil
	}

	file, err := anchor.OpenRegular()

	if file != nil {
		_ = file.Close()
		t.Fatalf("OpenRegular() file = %#v, want nil", file)
	}
	if !errors.Is(err, ErrFinalTargetChanged) {
		t.Fatalf("OpenRegular() error = %v, want ErrFinalTargetChanged", err)
	}
	if len(rejected) != maxFinalTargetAttempts {
		t.Fatalf("opened files = %d, want %d", len(rejected), maxFinalTargetAttempts)
	}
	for index, rejectedFile := range rejected {
		if _, statErr := rejectedFile.Stat(); statErr == nil {
			t.Fatalf("rejected file %d remained open", index)
		}
	}
}

func TestAnchoredOpen_bounds_repeated_not_exist_race(t *testing.T) {
	t.Parallel()

	anchor := newTestAnchor(t, filepath.Join(t.TempDir(), "target"))
	metadata := syntheticRegularFileInfo{name: "target"}
	anchor.finalOperations.lstat = func(*os.Root, string) (os.FileInfo, error) {
		return metadata, nil
	}
	attempts := 0
	anchor.finalOperations.open = func(finalOpenRequest) (finalOpenResult, error) {
		attempts++
		return finalOpenResult{}, os.ErrNotExist
	}

	file, err := anchor.OpenRegular()

	if file != nil {
		t.Fatalf("OpenRegular() file = %#v, want nil", file)
	}
	if !errors.Is(err, ErrFinalTargetChanged) {
		t.Fatalf("OpenRegular() error = %v, want ErrFinalTargetChanged", err)
	}
	if attempts != maxFinalTargetAttempts {
		t.Fatalf("open attempts = %d, want %d", attempts, maxFinalTargetAttempts)
	}
}

type syntheticRegularFileInfo struct {
	name string
}

func (info syntheticRegularFileInfo) Name() string  { return info.name }
func (syntheticRegularFileInfo) Size() int64        { return 0 }
func (syntheticRegularFileInfo) Mode() os.FileMode  { return 0 }
func (syntheticRegularFileInfo) ModTime() time.Time { return time.Time{} }
func (syntheticRegularFileInfo) IsDir() bool        { return false }
func (syntheticRegularFileInfo) Sys() any           { return nil }
