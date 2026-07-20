//go:build (unix && !aix) || windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const fixtureCompletionDeadline = 3 * time.Second

var errParentReplacementCancelled = errors.New("parent replacement cancelled")

type parentReplacementFixture struct {
	Root       string
	DirectoryA string
	DirectoryB string
	ParentPath string

	barrier         <-chan struct{}
	cancel          chan struct{}
	workerStarted   chan struct{}
	workerCompleted chan struct{}
	cancelOnce      sync.Once
	closeOnce       sync.Once
	resultMu        sync.Mutex
	replacementErr  error
	resultObserved  bool
	closeErr        error
}

func newParentReplacementFixture(t *testing.T, barrier <-chan struct{}) (*parentReplacementFixture, error) {
	t.Helper()

	root := t.TempDir()
	fixture := &parentReplacementFixture{
		Root:            root,
		DirectoryA:      filepath.Join(root, "parent-a"),
		DirectoryB:      filepath.Join(root, "parent-b"),
		ParentPath:      filepath.Join(root, "current-parent"),
		barrier:         barrier,
		cancel:          make(chan struct{}),
		workerStarted:   make(chan struct{}),
		workerCompleted: make(chan struct{}),
	}

	if err := os.Mkdir(fixture.DirectoryA, 0o700); err != nil {
		return nil, fmt.Errorf("create parent A: %w", err)
	}
	if err := os.Mkdir(fixture.DirectoryB, 0o700); err != nil {
		return nil, fmt.Errorf("create parent B: %w", err)
	}
	if err := os.WriteFile(filepath.Join(fixture.DirectoryA, "sentinel"), []byte("A"), 0o600); err != nil {
		return nil, fmt.Errorf("write parent A sentinel: %w", err)
	}
	if err := os.WriteFile(filepath.Join(fixture.DirectoryB, "sentinel"), []byte("B"), 0o600); err != nil {
		return nil, fmt.Errorf("write parent B sentinel: %w", err)
	}
	if err := createParentReplacementLink(fixture.DirectoryA, fixture.ParentPath); err != nil {
		return nil, fmt.Errorf("create parent link to A: %w", err)
	}

	go fixture.runReplacement()
	select {
	case <-fixture.workerStarted:
	case <-time.After(fixtureCompletionDeadline):
		fixture.cancelReplacement()
		return nil, errors.New("parent replacement worker did not reach barrier")
	}

	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close parent replacement fixture: %v", err)
		}
	})
	return fixture, nil
}

func (fixture *parentReplacementFixture) runReplacement() {
	close(fixture.workerStarted)
	select {
	case <-fixture.barrier:
		fixture.setReplacementResult(swapParentReplacementLink(fixture.DirectoryB, fixture.ParentPath))
	case <-fixture.cancel:
		fixture.setReplacementResult(errParentReplacementCancelled)
	}
	close(fixture.workerCompleted)
}

func (fixture *parentReplacementFixture) setReplacementResult(err error) {
	fixture.resultMu.Lock()
	defer fixture.resultMu.Unlock()
	fixture.replacementErr = err
}

func (fixture *parentReplacementFixture) readLinkedSentinel() (string, error) {
	content, err := os.ReadFile(filepath.Join(fixture.ParentPath, "sentinel"))
	if err != nil {
		return "", fmt.Errorf("read linked sentinel: %w", err)
	}
	return string(content), nil
}

func (fixture *parentReplacementFixture) replacementCompleted() bool {
	select {
	case <-fixture.workerCompleted:
		return true
	default:
		return false
	}
}

func (fixture *parentReplacementFixture) waitForReplacement(deadline time.Duration) error {
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case <-fixture.workerCompleted:
		fixture.resultMu.Lock()
		defer fixture.resultMu.Unlock()
		fixture.resultObserved = true
		return fixture.replacementErr
	case <-timer.C:
		return fmt.Errorf("parent replacement exceeded %s", deadline)
	}
}

func (fixture *parentReplacementFixture) cancelReplacement() {
	fixture.cancelOnce.Do(func() {
		close(fixture.cancel)
	})
}

func (fixture *parentReplacementFixture) Close() error {
	fixture.closeOnce.Do(func() {
		fixture.cancelReplacement()
		timer := time.NewTimer(fixtureCompletionDeadline)
		defer timer.Stop()

		var replacementErr error
		select {
		case <-fixture.workerCompleted:
			fixture.resultMu.Lock()
			if !fixture.resultObserved {
				replacementErr = fixture.replacementErr
			}
			fixture.resultMu.Unlock()
		case <-timer.C:
			replacementErr = fmt.Errorf("parent replacement cleanup exceeded %s", fixtureCompletionDeadline)
		}
		if errors.Is(replacementErr, errParentReplacementCancelled) {
			replacementErr = nil
		}
		fixture.closeErr = errors.Join(replacementErr, os.RemoveAll(fixture.Root))
	})
	return fixture.closeErr
}
