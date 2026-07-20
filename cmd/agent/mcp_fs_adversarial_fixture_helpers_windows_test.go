//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type specialFileFixture struct {
	Root                   string
	Directory              string
	ReparsePath            string
	ReparseSentinel        string
	ReparseCapabilityError error
	closeOnce              sync.Once
	closeErr               error
}

func createParentReplacementLink(target string, linkPath string) error {
	if err := os.Symlink(target, linkPath); err != nil {
		return fmt.Errorf("create Windows directory symlink (enable Developer Mode or grant SeCreateSymbolicLinkPrivilege): %w", err)
	}
	return nil
}

func swapParentReplacementLink(target string, linkPath string) error {
	replacementPath := linkPath + ".replacement"
	if err := os.Symlink(target, replacementPath); err != nil {
		return fmt.Errorf("create replacement Windows directory symlink: %w", err)
	}
	if err := os.Remove(linkPath); err != nil {
		_ = os.Remove(replacementPath)
		return fmt.Errorf("remove original Windows directory symlink: %w", err)
	}
	if err := os.Rename(replacementPath, linkPath); err != nil {
		return fmt.Errorf("install replacement Windows directory symlink: %w", err)
	}
	return nil
}

func newSpecialFileFixture(t *testing.T) *specialFileFixture {
	t.Helper()

	root := t.TempDir()
	reparseTarget := filepath.Join(root, "reparse-target")
	fixture := &specialFileFixture{
		Root:            root,
		Directory:       filepath.Join(root, "ordinary-directory"),
		ReparsePath:     filepath.Join(root, "directory-reparse-point"),
		ReparseSentinel: filepath.Join(root, "directory-reparse-point", "sentinel"),
	}
	if err := os.Mkdir(fixture.Directory, 0o700); err != nil {
		t.Fatalf("create ordinary fixture directory: %v", err)
	}
	if err := os.Mkdir(reparseTarget, 0o700); err != nil {
		t.Fatalf("create reparse target directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reparseTarget, "sentinel"), []byte("reparse"), 0o600); err != nil {
		t.Fatalf("write reparse target sentinel: %v", err)
	}
	if err := os.Symlink(reparseTarget, fixture.ReparsePath); err != nil {
		fixture.ReparseCapabilityError = fmt.Errorf("create Windows directory symlink (enable Developer Mode or grant SeCreateSymbolicLinkPrivilege): %w", err)
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close Windows special-file fixture: %v", err)
		}
	})
	return fixture
}

func (fixture *specialFileFixture) Close() error {
	fixture.closeOnce.Do(func() {
		fixture.closeErr = os.RemoveAll(fixture.Root)
	})
	return fixture.closeErr
}
