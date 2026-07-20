package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

const pathLockTestTimeout = 2 * time.Second

func TestFsPathLocker_SerializesDistinctPathsInSameStripe(t *testing.T) {
	// Given
	locker := newFsPathLocker()
	firstPath, secondPath := pathsInSameStripe(t, locker)
	firstUnlock := locker.lock(firstPath)
	secondAttempted := make(chan *sync.Mutex)
	allowStripeLock := make(chan struct{})
	secondEntered := make(chan struct{})
	secondDone := make(chan struct{})
	var allowOnce sync.Once
	allowLockAttempt := func() { allowOnce.Do(func() { close(allowStripeLock) }) }
	locker.beforeStripeLockForTest = func(stripe *sync.Mutex) {
		secondAttempted <- stripe
		<-allowStripeLock
	}
	locker.afterStripeLockForTest = func() { close(secondEntered) }
	defer func() {
		allowLockAttempt()
		firstUnlock()
		awaitPathLockSignal(t, secondDone, "same-stripe second completion")
	}()

	// When
	go func() {
		unlock := locker.lock(secondPath)
		unlock()
		close(secondDone)
	}()

	// Then
	if got := awaitPathLockStripe(t, secondAttempted, "same-stripe production mutex attempt"); got != locker.stripe(firstPath) {
		t.Fatal("second path attempted a different stripe")
	}
	allowLockAttempt()
	assertPathLockBlocked(t, secondEntered, "same-stripe second acquisition")
	firstUnlock()
	awaitPathLockSignal(t, secondEntered, "same-stripe second acquisition")
	awaitPathLockSignal(t, secondDone, "same-stripe second completion")
}

func TestFsPathLocker_AllowsDistinctStripeOperationsToOverlap(t *testing.T) {
	locker := newFsPathLocker()
	firstPath, secondPath := pathsInDistinctStripes(t, locker)
	firstUnlock := locker.lock(firstPath)
	secondEntered := make(chan struct{})
	secondRelease := make(chan struct{})
	secondDone := make(chan struct{})
	defer func() {
		close(secondRelease)
		firstUnlock()
		awaitPathLockSignal(t, secondDone, "distinct-stripe second completion")
	}()

	go func() {
		unlock := locker.lock(secondPath)
		close(secondEntered)
		<-secondRelease
		unlock()
		close(secondDone)
	}()

	awaitPathLockSignal(t, secondEntered, "distinct-stripe second acquisition")
}

func pathsInSameStripe(t *testing.T, locker *fsPathLocker) (string, string) {
	t.Helper()
	firstPath := "/tmp/path-lock-same-stripe/first"
	firstStripe := locker.stripe(firstPath)
	for candidateIndex := 0; ; candidateIndex++ {
		candidatePath := fmt.Sprintf("/tmp/path-lock-same-stripe/%d", candidateIndex)
		if candidatePath != firstPath && locker.stripe(candidatePath) == firstStripe {
			return firstPath, candidatePath
		}
	}
}

func pathsInDistinctStripes(t *testing.T, locker *fsPathLocker) (string, string) {
	t.Helper()
	firstPath := "/tmp/path-lock-distinct-stripe/first"
	firstStripe := locker.stripe(firstPath)
	for candidateIndex := 0; ; candidateIndex++ {
		candidatePath := fmt.Sprintf("/tmp/path-lock-distinct-stripe/%d", candidateIndex)
		if locker.stripe(candidatePath) != firstStripe {
			return firstPath, candidatePath
		}
	}
}

func awaitPathLockStripe(t *testing.T, attempted <-chan *sync.Mutex, description string) *sync.Mutex {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), pathLockTestTimeout)
	defer cancel()
	select {
	case stripe := <-attempted:
		return stripe
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
		return nil
	}
}

func assertPathLockBlocked(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), pathLockTestTimeout)
	defer cancel()
	select {
	case <-signal:
		t.Fatalf("%s completed while its stripe remained locked", description)
	case <-ctx.Done():
	}
}

func awaitPathLockSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), pathLockTestTimeout)
	defer cancel()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
	}
}
