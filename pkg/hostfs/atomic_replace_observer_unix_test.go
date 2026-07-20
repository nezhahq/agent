//go:build unix

package hostfs

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestAnchoredAtomicReplace_ObserverProvesOldThenNewWithoutPartialReads(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "observed.txt")
	oldContent := bytes.Repeat([]byte("A"), 64*1024)
	newContent := bytes.Repeat([]byte("B"), 64*1024)
	if err := os.WriteFile(target, oldContent, 0o600); err != nil {
		t.Fatalf("write old target: %v", err)
	}
	anchor := newTestAnchor(t, target)
	allowRename := make(chan struct{})
	operations := anchor.atomicOperations
	operations.beforeRename = func() { <-allowRename }
	anchor.atomicOperations = operations
	observer := startAtomicReplaceObserver(target, oldContent, newContent, os.ReadFile)
	defer observer.stopAndWait()
	observer.waitForOld(t)

	// When
	close(allowRename)
	result, err := anchor.AtomicReplace(newContent, 0o600)
	if err != nil {
		observer.stopAndWait()
		t.Fatalf("AtomicReplace(): %v", err)
	}
	observer.markCommitted()
	observer.waitForNew(t)

	// Then
	assertDefaultAtomicReplaceResult(t, result, err)
}

func TestAtomicReplaceObserver_ReadErrorStopsAndJoins(t *testing.T) {
	// Given
	readErr := errors.New("injected observer read failure")
	readCalled := make(chan struct{})
	readFile := func(string) ([]byte, error) {
		close(readCalled)
		return nil, readErr
	}
	observer := startAtomicReplaceObserver("unused", []byte("old"), []byte("new"), readFile)

	// When
	<-readCalled
	err := observer.waitForOldError()
	observer.stopAndWait()

	// Then
	if !errors.Is(err, readErr) {
		t.Fatalf("observer error = %v, want injected read error", err)
	}
}

type atomicReplaceObserver struct {
	oldObserved chan struct{}
	commitDone  chan struct{}
	newObserved chan struct{}
	readerErr   chan error
	stop        chan struct{}
	readers     sync.WaitGroup
	stopOnce    sync.Once
	commitOnce  sync.Once
}

func startAtomicReplaceObserver(target string, oldContent, newContent []byte, readFile func(string) ([]byte, error)) *atomicReplaceObserver {
	observer := &atomicReplaceObserver{
		oldObserved: make(chan struct{}),
		commitDone:  make(chan struct{}),
		newObserved: make(chan struct{}),
		readerErr:   make(chan error, 1),
		stop:        make(chan struct{}),
	}
	observer.readers.Add(1)
	go observer.run(target, oldContent, newContent, readFile)
	return observer
}

func (observer *atomicReplaceObserver) run(target string, oldContent, newContent []byte, readFile func(string) ([]byte, error)) {
	defer observer.readers.Done()
	oldSignaled := false
	newSignaled := false
	for {
		select {
		case <-observer.stop:
			return
		default:
		}
		content, err := readFile(target)
		if err != nil {
			observer.readerErr <- err
			return
		}
		switch {
		case bytes.Equal(content, oldContent):
			if !oldSignaled {
				close(observer.oldObserved)
				oldSignaled = true
			}
		case bytes.Equal(content, newContent):
			select {
			case <-observer.commitDone:
				if !newSignaled {
					close(observer.newObserved)
					newSignaled = true
				}
			default:
			}
		default:
			observer.readerErr <- errors.New("observer read partial content")
			return
		}
	}
}

func (observer *atomicReplaceObserver) waitForOld(t *testing.T) {
	t.Helper()
	select {
	case <-observer.oldObserved:
	case err := <-observer.readerErr:
		observer.stopAndWait()
		t.Fatalf("observer before commit: %v", err)
	}
}

func (observer *atomicReplaceObserver) waitForOldError() error {
	select {
	case <-observer.oldObserved:
		return errors.New("observer unexpectedly read old content")
	case err := <-observer.readerErr:
		return err
	}
}

func (observer *atomicReplaceObserver) waitForNew(t *testing.T) {
	t.Helper()
	select {
	case <-observer.newObserved:
	case err := <-observer.readerErr:
		observer.stopAndWait()
		t.Fatalf("observer after commit: %v", err)
	}
}

func (observer *atomicReplaceObserver) markCommitted() {
	observer.commitOnce.Do(func() { close(observer.commitDone) })
}

func (observer *atomicReplaceObserver) stopAndWait() {
	observer.stopOnce.Do(func() { close(observer.stop) })
	observer.readers.Wait()
}
