//go:build (unix && !aix) || windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParentReplacementFixture_SwapsFromAToBAfterBarrier(t *testing.T) {
	// Given
	barrier := make(chan struct{})
	fixture, capabilityErr := newParentReplacementFixture(t, barrier)
	if capabilityErr != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("[blocked: native reparse capability] %v", capabilityErr)
		}
		t.Fatalf("create parent replacement fixture: %v", capabilityErr)
	}

	before, err := fixture.readLinkedSentinel()
	if err != nil {
		t.Fatalf("read A sentinel: %v", err)
	}
	if before != "A" {
		t.Fatalf("sentinel before barrier = %q, want A", before)
	}
	assertParentPathIsSymlink(t, fixture.ParentPath)
	if fixture.replacementCompleted() {
		t.Fatal("parent replacement completed before the barrier opened")
	}
	t.Logf("parent sentinel before barrier: %s", before)

	// When
	close(barrier)
	if err := fixture.waitForReplacement(fixtureCompletionDeadline); err != nil {
		t.Fatalf("wait for parent replacement: %v", err)
	}

	// Then
	after, err := fixture.readLinkedSentinel()
	if err != nil {
		t.Fatalf("read B sentinel: %v", err)
	}
	if after != "B" {
		t.Fatalf("sentinel after barrier = %q, want B", after)
	}
	assertParentPathIsSymlink(t, fixture.ParentPath)
	t.Logf("parent sentinel after barrier: %s", after)
}

func TestParentReplacementFixture_ReportsPreexistingReplacementPath(t *testing.T) {
	// Given
	barrier := make(chan struct{})
	fixture, capabilityErr := newParentReplacementFixture(t, barrier)
	if capabilityErr != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("[blocked: native reparse capability] %v", capabilityErr)
		}
		t.Fatalf("create parent replacement fixture: %v", capabilityErr)
	}
	if err := os.WriteFile(fixture.ParentPath+".replacement", []byte("occupied"), 0o600); err != nil {
		t.Fatalf("occupy replacement path: %v", err)
	}

	// When
	close(barrier)
	err := fixture.waitForReplacement(fixtureCompletionDeadline)

	// Then
	if err == nil {
		t.Fatal("preexisting replacement path must fail the swap")
	}
	sentinel, readErr := fixture.readLinkedSentinel()
	if readErr != nil {
		t.Fatalf("read unchanged A sentinel: %v", readErr)
	}
	if sentinel != "A" {
		t.Fatalf("sentinel after failed replacement = %q, want A", sentinel)
	}
}

func TestParentReplacementFixture_CancellationStopsBlockedReplacement(t *testing.T) {
	// Given
	barrier := make(chan struct{})
	fixture, capabilityErr := newParentReplacementFixture(t, barrier)
	if capabilityErr != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("[blocked: native reparse capability] %v", capabilityErr)
		}
		t.Fatalf("create parent replacement fixture: %v", capabilityErr)
	}

	// When
	fixture.cancelReplacement()
	err := fixture.waitForReplacement(fixtureCompletionDeadline)

	// Then
	if !errors.Is(err, errParentReplacementCancelled) {
		t.Fatalf("cancelled replacement error = %v, want %v", err, errParentReplacementCancelled)
	}
}

func TestParentReplacementFixture_CleanupIsIdempotent(t *testing.T) {
	// Given
	barrier := make(chan struct{})
	fixture, capabilityErr := newParentReplacementFixture(t, barrier)
	if capabilityErr != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("[blocked: native reparse capability] %v", capabilityErr)
		}
		t.Fatalf("create parent replacement fixture: %v", capabilityErr)
	}
	root := fixture.Root

	// When
	if err := fixture.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatalf("close fixture twice: %v", err)
	}

	// Then
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("fixture root remains after cleanup: %v", err)
	}
}

func assertParentPathIsSymlink(t *testing.T, parentPath string) {
	t.Helper()
	info, err := os.Lstat(filepath.Clean(parentPath))
	if err != nil {
		t.Fatalf("lstat parent link: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("parent path mode = %v, want symlink", info.Mode())
	}
}
