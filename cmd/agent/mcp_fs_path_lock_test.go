package main

import (
	"runtime"
	"sync"
	"testing"
)

// On case-insensitive filesystems (Windows, default macOS APFS) the same
// file is reachable through case-variant paths. The lock key must fold to
// one stripe for those GOOS, or two concurrent if_match writers using
// `C:\Data\a.txt` and `c:\data\A.TXT` race the same file through different
// stripes and the optimistic-lock guarantee is lost. POSIX stays
// case-sensitive, so distinct case there must keep distinct keys.
func TestFsPathLockKeyCaseFolding(t *testing.T) {
	const upper = `C:\Data\A.TXT`
	const lower = `c:\data\a.txt`

	sameKey := lockKeyForTest(upper) == lockKeyForTest(lower)
	caseInsensitiveFS := runtime.GOOS == "windows" || runtime.GOOS == "darwin"

	if caseInsensitiveFS && !sameKey {
		t.Fatalf("on %s case-variant paths must share a lock key", runtime.GOOS)
	}
	if !caseInsensitiveFS && sameKey {
		t.Fatalf("on %s case-variant paths must keep distinct lock keys", runtime.GOOS)
	}
}

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
