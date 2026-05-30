package main

import (
	"sync"
	"testing"
)

// M4 regression: if_match_sha256 is a TOCTOU precondition. Two concurrent
// MCP writers targeting the same path can both hash the old contents,
// both pass IfMatchSHA256, and the later rename silently overwrites the
// earlier write. fsPathMu serialises per-path so the hash+rename window
// is atomic with respect to other agent MCP writers.
func TestFsPathMu_SamePathSerializes(t *testing.T) {
	const path = "/tmp/m4-serialize"
	unlock1 := fsPathMu.lock(path)
	defer unlock1()

	released := make(chan struct{})
	go func() {
		unlock2 := fsPathMu.lock(path)
		defer unlock2()
		close(released)
	}()

	select {
	case <-released:
		t.Fatal("second locker must block until the first unlocks (same path)")
	default:
	}
}

func TestFsPathMu_DifferentPathsAreParallel(t *testing.T) {
	unlock1 := fsPathMu.lock("/tmp/m4-a")
	defer unlock1()

	done := make(chan struct{})
	go func() {
		unlock2 := fsPathMu.lock("/tmp/m4-b")
		defer unlock2()
		close(done)
	}()

	<-done
}

func TestFsPathMu_HandlesManyConcurrentAcquires(t *testing.T) {
	const path = "/tmp/m4-many"
	const n = 64
	var wg sync.WaitGroup
	var counter int
	var counterMu sync.Mutex

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := fsPathMu.lock(path)
			counterMu.Lock()
			counter++
			counterMu.Unlock()
			unlock()
		}()
	}
	wg.Wait()
	if counter != n {
		t.Fatalf("expected %d acquires to all succeed, got %d", n, counter)
	}
}
