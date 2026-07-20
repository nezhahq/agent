//go:build unix && !aix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const fifoBlockingObservationDeadline = 100 * time.Millisecond

type fifoOpenResult struct {
	file *os.File
	err  error
}

func TestSpecialFileFixture_CreatesUnixTargets(t *testing.T) {
	// Given
	fixture := newSpecialFileFixture(t)

	// When / Then
	assertFixtureMode(t, fixture.Directory, os.ModeDir)
	assertFixtureMode(t, fixture.RegularFile, 0)
	assertFixtureMode(t, fixture.FIFO, os.ModeNamedPipe)
	assertFixtureMode(t, fixture.Socket, os.ModeSocket)
	assertFixtureMode(t, fixture.Symlink, os.ModeSymlink)
}

func TestSpecialFileFixture_CreatesUnixSocketWhenTMPDIRIsLong(t *testing.T) {
	// Given
	tmpRoot, err := os.MkdirTemp("/tmp", "agent-long-tmpdir-")
	if err != nil {
		t.Fatalf("create long TMPDIR root: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(tmpRoot); err != nil {
			t.Errorf("remove long TMPDIR root: %v", err)
		}
	})
	longTMPDIR := filepath.Join(tmpRoot, strings.Repeat("long-tmpdir-", 10))
	if err := os.Mkdir(longTMPDIR, 0o700); err != nil {
		t.Fatalf("create long TMPDIR: %v", err)
	}
	t.Setenv("TMPDIR", longTMPDIR)

	// When
	fixture := newSpecialFileFixture(t)

	// Then
	if !strings.HasPrefix(fixture.Root, longTMPDIR) {
		t.Fatalf("fixture root = %q, want prefix %q", fixture.Root, longTMPDIR)
	}
	if strings.HasPrefix(fixture.Socket, longTMPDIR) {
		t.Fatalf("fixture socket inherited long TMPDIR: %q", fixture.Socket)
	}
	assertFixtureMode(t, fixture.Socket, os.ModeSocket)
}

func TestSpecialFileFixture_CleanupIsIdempotent(t *testing.T) {
	// Given
	fixture := newSpecialFileFixture(t)
	root := fixture.Root
	socketDirectory := fixture.socketDirectory

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
	if _, err := os.Lstat(socketDirectory); !os.IsNotExist(err) {
		t.Fatalf("fixture socket directory remains after cleanup: %v", err)
	}
}

func TestSpecialFileFixture_FIFOBlockingOpenHitsDeadlineThenUnblocks(t *testing.T) {
	// Given
	fixture := newSpecialFileFixture(t)
	started := make(chan struct{})
	opened := make(chan fifoOpenResult, 1)
	go func() {
		close(started)
		file, err := os.Open(fixture.FIFO)
		opened <- fifoOpenResult{file: file, err: err}
	}()

	select {
	case <-started:
	case <-time.After(fixtureCompletionDeadline):
		t.Fatal("FIFO reader goroutine did not start")
	}

	// When
	select {
	case result := <-opened:
		if result.file != nil {
			_ = result.file.Close()
		}
		t.Fatalf("blocking FIFO open completed before a writer arrived: %v", result.err)
	case <-time.After(fifoBlockingObservationDeadline):
		t.Logf("FIFO blocking-open deadline observed after %s", fifoBlockingObservationDeadline)
	}

	keeperFD, err := unix.Open(fixture.FIFO, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open FIFO keeper: %v", err)
	}
	defer unix.Close(keeperFD)

	// Then
	select {
	case result := <-opened:
		if result.err != nil {
			t.Fatalf("FIFO reader failed after writer arrived: %v", result.err)
		}
		if err := result.file.Close(); err != nil {
			t.Fatalf("close FIFO reader: %v", err)
		}
	case <-time.After(fixtureCompletionDeadline):
		t.Fatal("FIFO reader remained blocked after a writer arrived")
	}
}

func assertFixtureMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat %q: %v", path, err)
	}
	if want == 0 {
		if !info.Mode().IsRegular() {
			t.Fatalf("mode for %q = %v, want regular file", path, info.Mode())
		}
		return
	}
	if info.Mode()&want == 0 {
		t.Fatalf("mode for %q = %v, want flag %v", path, info.Mode(), want)
	}
}
