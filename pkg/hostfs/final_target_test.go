package hostfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredClassify_identifies_absent_regular_and_directory(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	regularPath := filepath.Join(directory, "regular.txt")
	directoryPath := filepath.Join(directory, "child")
	if err := os.WriteFile(regularPath, []byte("regular"), 0o600); err != nil {
		t.Fatalf("create regular file: %v", err)
	}
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatalf("create directory: %v", err)
	}

	tests := []struct {
		name string
		path string
		want FinalTargetType
	}{
		{name: "absent", path: filepath.Join(directory, "absent"), want: FinalTargetAbsent},
		{name: "regular", path: regularPath, want: FinalTargetRegular},
		{name: "directory", path: directoryPath, want: FinalTargetDirectory},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor := newTestAnchor(t, test.path)

			got, err := anchor.ClassifyFinal()

			if err != nil {
				t.Fatalf("ClassifyFinal(): %v", err)
			}
			if got != test.want {
				t.Fatalf("ClassifyFinal() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAnchoredOpenRegular_opens_regular_and_rejects_directory(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	regularPath := filepath.Join(directory, "regular.txt")
	if err := os.WriteFile(regularPath, []byte("anchored-content"), 0o600); err != nil {
		t.Fatalf("create regular file: %v", err)
	}
	regularAnchor := newTestAnchor(t, regularPath)
	directoryAnchor := newTestAnchor(t, directory)

	file, err := regularAnchor.OpenRegular()
	if err != nil {
		t.Fatalf("OpenRegular(): %v", err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Errorf("close regular file: %v", err)
		}
	})
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read regular file: %v", err)
	}
	if got := string(content); got != "anchored-content" {
		t.Fatalf("regular content = %q, want anchored-content", got)
	}

	rejected, err := directoryAnchor.OpenRegular()
	if rejected != nil {
		_ = rejected.Close()
		t.Fatalf("OpenRegular(directory) file = %#v, want nil", rejected)
	}
	assertFinalTargetTypeError(t, err, FinalTargetRegular, FinalTargetDirectory)
}

func TestAnchoredOpenDirectory_opens_directory_and_rejects_regular(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	regularPath := filepath.Join(directory, "regular.txt")
	if err := os.WriteFile(regularPath, []byte("regular"), 0o600); err != nil {
		t.Fatalf("create regular file: %v", err)
	}
	directoryAnchor := newTestAnchor(t, directory)
	regularAnchor := newTestAnchor(t, regularPath)

	opened, err := directoryAnchor.OpenDirectory()
	if err != nil {
		t.Fatalf("OpenDirectory(): %v", err)
	}
	t.Cleanup(func() {
		if err := opened.Close(); err != nil {
			t.Errorf("close directory: %v", err)
		}
	})
	info, err := opened.Stat()
	if err != nil {
		t.Fatalf("stat opened directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("opened mode = %s, want directory", info.Mode())
	}

	rejected, err := regularAnchor.OpenDirectory()
	if rejected != nil {
		_ = rejected.Close()
		t.Fatalf("OpenDirectory(regular) file = %#v, want nil", rejected)
	}
	assertFinalTargetTypeError(t, err, FinalTargetDirectory, FinalTargetRegular)
}

func TestAnchoredOpen_missing_target_returns_absent_type(t *testing.T) {
	t.Parallel()

	anchor := newTestAnchor(t, filepath.Join(t.TempDir(), "missing"))

	file, err := anchor.OpenRegular()

	if file != nil {
		_ = file.Close()
		t.Fatalf("OpenRegular(missing) file = %#v, want nil", file)
	}
	assertFinalTargetTypeError(t, err, FinalTargetRegular, FinalTargetAbsent)
}

func newTestAnchor(t *testing.T, path string) *Anchor {
	t.Helper()

	anchor, err := New(path)
	if err != nil {
		t.Fatalf("New(%q): %v", path, err)
	}
	t.Cleanup(func() {
		if err := anchor.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	})
	return anchor
}

func assertFinalTargetTypeError(t *testing.T, err error, expected, actual FinalTargetType) {
	t.Helper()

	var typeErr *FinalTargetTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("error type = %T (%v), want *FinalTargetTypeError", err, err)
	}
	if typeErr.Expected != expected || typeErr.Actual != actual {
		t.Fatalf("type error = expected %v actual %v, want expected %v actual %v", typeErr.Expected, typeErr.Actual, expected, actual)
	}
}
