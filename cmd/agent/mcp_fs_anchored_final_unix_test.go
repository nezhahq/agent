//go:build unix && !aix

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/hostfs"
)

func TestAnchoredOpen_parent_replacement_cannot_redirect_final_open(t *testing.T) {
	barrier := make(chan struct{})
	fixture, err := newParentReplacementFixture(t, barrier)
	if err != nil {
		t.Fatalf("create parent replacement fixture: %v", err)
	}
	anchor, err := hostfs.New(filepath.Join(fixture.ParentPath, "sentinel"))
	if err != nil {
		t.Fatalf("anchor parent A: %v", err)
	}
	t.Cleanup(func() {
		if err := anchor.Close(); err != nil {
			t.Errorf("close Anchor: %v", err)
		}
	})
	close(barrier)
	if err := fixture.waitForReplacement(fixtureCompletionDeadline); err != nil {
		t.Fatalf("replace parent with B: %v", err)
	}

	file, err := anchor.OpenRegular()
	if err != nil {
		t.Fatalf("OpenRegular(): %v", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close anchored file: %v", err)
		}
	}()
	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read anchored file: %v", err)
	}
	if got := string(content); got != "A" {
		t.Fatalf("anchored content = %q, want A", got)
	}
	pathnameContent, err := os.ReadFile(filepath.Join(fixture.ParentPath, "sentinel"))
	if err != nil {
		t.Fatalf("read replaced pathname: %v", err)
	}
	if got := string(pathnameContent); got != "B" {
		t.Fatalf("pathname content = %q, want B", got)
	}
}

func TestAnchoredOpen_parent_replacement_cannot_redirect_directory_open(t *testing.T) {
	barrier := make(chan struct{})
	fixture, err := newParentReplacementFixture(t, barrier)
	if err != nil {
		t.Fatalf("create parent replacement fixture: %v", err)
	}
	directoryA := filepath.Join(fixture.DirectoryA, "child")
	directoryB := filepath.Join(fixture.DirectoryB, "child")
	if err := os.Mkdir(directoryA, 0o700); err != nil {
		t.Fatalf("create directory A child: %v", err)
	}
	if err := os.Mkdir(directoryB, 0o700); err != nil {
		t.Fatalf("create directory B child: %v", err)
	}
	anchor, err := hostfs.New(filepath.Join(fixture.ParentPath, "child"))
	if err != nil {
		t.Fatalf("anchor directory under parent A: %v", err)
	}
	t.Cleanup(func() { _ = anchor.Close() })
	close(barrier)
	if err := fixture.waitForReplacement(fixtureCompletionDeadline); err != nil {
		t.Fatalf("replace parent with B: %v", err)
	}

	directory, err := anchor.OpenDirectory()
	if err != nil {
		t.Fatalf("OpenDirectory(): %v", err)
	}
	defer func() { _ = directory.Close() }()
	openedInfo, err := directory.Stat()
	if err != nil {
		t.Fatalf("stat opened directory: %v", err)
	}
	directoryAInfo, err := os.Stat(directoryA)
	if err != nil {
		t.Fatalf("stat directory A child: %v", err)
	}
	if !os.SameFile(openedInfo, directoryAInfo) {
		t.Fatal("anchored directory open was redirected away from A")
	}
	pathnameInfo, err := os.Stat(filepath.Join(fixture.ParentPath, "child"))
	if err != nil {
		t.Fatalf("stat replaced pathname directory: %v", err)
	}
	directoryBInfo, err := os.Stat(directoryB)
	if err != nil {
		t.Fatalf("stat directory B child: %v", err)
	}
	if !os.SameFile(pathnameInfo, directoryBInfo) {
		t.Fatal("replaced pathname directory does not reference B")
	}
}

func TestAnchoredRejectsFinal_unix_special_files_boundedly(t *testing.T) {
	fixture := newSpecialFileFixture(t)
	tests := []struct {
		name string
		path string
		want hostfs.FinalTargetType
	}{
		{name: "FIFO", path: fixture.FIFO, want: hostfs.FinalTargetFIFO},
		{name: "socket", path: fixture.Socket, want: hostfs.FinalTargetSocket},
		{name: "symlink", path: fixture.Symlink, want: hostfs.FinalTargetSymlinkReparse},
		{name: "device", path: "/dev/null", want: hostfs.FinalTargetDeviceOther},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor, err := hostfs.New(test.path)
			if err != nil {
				t.Fatalf("New(%q): %v", test.path, err)
			}
			defer func() { _ = anchor.Close() }()
			result := make(chan error, 1)
			go func() {
				file, openErr := anchor.OpenRegular()
				if file != nil {
					_ = file.Close()
				}
				result <- openErr
			}()

			select {
			case openErr := <-result:
				var typeErr *hostfs.FinalTargetTypeError
				if !errors.As(openErr, &typeErr) {
					t.Fatalf("error type = %T (%v), want *FinalTargetTypeError", openErr, openErr)
				}
				if typeErr.Actual != test.want {
					t.Fatalf("actual type = %v, want %v", typeErr.Actual, test.want)
				}
			case <-time.After(fixtureCompletionDeadline):
				t.Fatalf("OpenRegular(%s) exceeded %s", test.name, fixtureCompletionDeadline)
			}
		})
	}
}
