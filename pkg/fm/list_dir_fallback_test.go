package fm

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func listDirWithDeadline(t *testing.T, task *Task, dir string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- task.listDir(dir) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listDir returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listDir did not return: it keeps retrying an unreadable home directory")
	}
}

// Service accounts commonly have a home such as /nonexistent. The fallback
// must be tried once and then reported, not retried in a busy loop.
func TestTask_ListDirReportsErrorWhenHomeFallbackIsUnreadable(t *testing.T) {
	originalHomeDir := currentUserHomeDir
	t.Cleanup(func() { currentUserHomeDir = originalHomeDir })
	missingHome := filepath.Join(t.TempDir(), "missing-home")
	currentUserHomeDir = func() (string, error) { return missingHome, nil }

	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)

	listDirWithDeadline(t, task, filepath.Join(t.TempDir(), "missing-dir"))

	frames := stream.frames()
	if len(frames) != 1 {
		t.Fatalf("sent %d frames, want exactly one error frame", len(frames))
	}
	if !bytes.HasPrefix(frames[0], errorIdentifier) {
		t.Fatalf("frame = %q, want an error frame", frames[0])
	}
}

func TestTask_ListDirFallsBackToReadableHome(t *testing.T) {
	originalHomeDir := currentUserHomeDir
	t.Cleanup(func() { currentUserHomeDir = originalHomeDir })
	home := t.TempDir()
	currentUserHomeDir = func() (string, error) { return home, nil }

	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)

	listDirWithDeadline(t, task, filepath.Join(t.TempDir(), "missing-dir"))

	frames := stream.frames()
	if len(frames) != 1 {
		t.Fatalf("sent %d frames, want exactly one listing frame", len(frames))
	}
	if !bytes.Contains(frames[0], []byte(home)) {
		t.Fatalf("listing frame %q does not name the home directory %q", frames[0], home)
	}
}

func TestTask_ListDirReportsHomeLookupFailure(t *testing.T) {
	originalHomeDir := currentUserHomeDir
	t.Cleanup(func() { currentUserHomeDir = originalHomeDir })
	currentUserHomeDir = func() (string, error) { return "", errors.New("no passwd entry") }

	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)

	listDirWithDeadline(t, task, filepath.Join(t.TempDir(), "missing-dir"))

	frames := stream.frames()
	if len(frames) != 1 || !bytes.Contains(frames[0], []byte("no passwd entry")) {
		t.Fatalf("frames = %q, want one error frame carrying the lookup failure", frames)
	}
}
