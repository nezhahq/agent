//go:build windows

package hostfs

import (
	"errors"
	"testing"
)

func TestDirectorySync_WindowsCreatedParentIsSuccessfulNoOp(t *testing.T) {
	// When
	err := syncCreatedParentDirectory(nil)

	// Then
	if err != nil {
		t.Fatalf("syncCreatedParentDirectory() error = %v, want nil", err)
	}
}

func TestDirectorySync_WindowsReplacementReportsUnsupported(t *testing.T) {
	// When
	err := syncReplacementDirectory(nil)

	// Then
	var unsupportedErr *DirectorySyncUnsupportedError
	if !errors.As(err, &unsupportedErr) {
		t.Fatalf("syncReplacementDirectory() error = %T %v, want *DirectorySyncUnsupportedError", err, err)
	}
	if !errors.Is(err, ErrDirectorySyncUnsupported) {
		t.Fatalf("syncReplacementDirectory() error = %v, want ErrDirectorySyncUnsupported", err)
	}
}
