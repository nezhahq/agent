//go:build unix

package hostfs

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredHash_ParentPathReplacementCannotRedirect(t *testing.T) {
	// Given
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir parent: %v", err)
	}
	target := filepath.Join(parent, "target.txt")
	writeTestFile(t, target, "original")
	anchor := newTestAnchor(t, target)
	moved := filepath.Join(base, "moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatalf("rename parent: %v", err)
	}
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("mkdir replacement: %v", err)
	}
	writeTestFile(t, target, "replacement")
	wantBytes := sha256.Sum256([]byte("original"))
	want := hex.EncodeToString(wantBytes[:])

	// When
	got, err := anchor.SHA256()

	// Then
	if err != nil || got != want {
		t.Fatalf("SHA256() = %q/%v, want original digest %q", got, err, want)
	}
}
