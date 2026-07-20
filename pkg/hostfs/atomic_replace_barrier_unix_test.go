//go:build unix

package hostfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnchoredAtomicReplace_PostRevalidationSymlinkRaceNeverFollowsTarget(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	secret := filepath.Join(directory, "secret.txt")
	writeTestFile(t, target, "old-content")
	writeTestFile(t, secret, "secret-content")
	anchor := newTestAnchor(t, target)
	revalidated := make(chan struct{})
	allowRename := make(chan struct{})
	operations := anchor.atomicOperations
	operations.beforeRename = func() {
		close(revalidated)
		<-allowRename
	}
	anchor.atomicOperations = operations
	resultCh := make(chan AtomicReplaceResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := anchor.AtomicReplace([]byte("new-content"), 0o600)
		resultCh <- result
		errCh <- err
	}()
	<-revalidated
	if err := os.Remove(target); err != nil {
		t.Fatalf("remove target after revalidation: %v", err)
	}
	if err := os.Symlink(secret, target); err != nil {
		t.Fatalf("insert symlink after revalidation: %v", err)
	}
	close(allowRename)

	// When
	result := <-resultCh
	err := <-errCh

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
	assertFileContent(t, secret, "secret-content")
	assertFileContent(t, target, "new-content")
	assertNoAtomicTempEntries(t, directory, filepath.Base(target))
}
