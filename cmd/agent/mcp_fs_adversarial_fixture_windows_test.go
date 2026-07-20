//go:build windows

package main

import (
	"os"
	"testing"
)

func TestSpecialFileFixture_OrdinaryDirectorySucceedsOnWindows(t *testing.T) {
	// Given
	fixture := newSpecialFileFixture(t)

	// When
	info, err := os.Stat(fixture.Directory)

	// Then
	if err != nil {
		t.Fatalf("stat ordinary fixture directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("ordinary fixture path mode = %v, want directory", info.Mode())
	}
}

func TestSpecialFileFixture_ReparseTargetCapabilityOnWindows(t *testing.T) {
	// Given
	fixture := newSpecialFileFixture(t)
	if fixture.ReparseCapabilityError != nil {
		t.Skipf("[blocked: native reparse capability] %v", fixture.ReparseCapabilityError)
	}

	// When
	content, err := os.ReadFile(fixture.ReparseSentinel)

	// Then
	if err != nil {
		t.Fatalf("read sentinel through reparse target: %v", err)
	}
	if string(content) != "reparse" {
		t.Fatalf("reparse sentinel = %q, want reparse", content)
	}
}

func TestSpecialFileFixture_CleanupIsIdempotentOnWindows(t *testing.T) {
	// Given
	fixture := newSpecialFileFixture(t)
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
