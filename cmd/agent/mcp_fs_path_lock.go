package main

import (
	"hash/fnv"
	"runtime"
	"strings"
	"sync"
)

// fsPathLockStripes is the fixed number of mutexes the locker holds. Paths
// hash into a stripe, so memory stays constant regardless of how many unique
// paths a remote caller touches.
const fsPathLockStripes = 1024

// fsPathLocker serialises in-process MCP writers that target the same
// agent-side path. The if_match_sha256 precondition is a classic
// check-then-act: without this lock two MCP callers can both hash the
// old file, both pass the precondition, and the second rename silently
// overwrites the first writer's update.
//
// Striping (rather than a per-path entry) bounds memory: an attacker can no
// longer grow an unbounded map by locking endless unique paths. Distinct
// paths that hash to the same stripe serialise — acceptable, since the lock
// is only held across a short check-then-rename window. The lock does NOT
// defend against non-MCP writers; callers must layer a platform-level file
// lock for that, documented at the fs.write / fs.transfer upload sites.
type fsPathLocker struct {
	stripes [fsPathLockStripes]sync.Mutex
}

func newFsPathLocker() *fsPathLocker {
	return &fsPathLocker{}
}

// normalizeLockKey folds case on case-insensitive filesystems so the same
// file reached through case-variant paths maps to one stripe. Windows and
// the default macOS volume are case-insensitive; POSIX is case-sensitive,
// where distinct case is a distinct file and must keep a distinct key.
func normalizeLockKey(path string) string {
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.ToLower(path)
	}
	return path
}

func (l *fsPathLocker) stripe(path string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(normalizeLockKey(path)))
	return &l.stripes[h.Sum32()%fsPathLockStripes]
}

// lock acquires the path's stripe mutex and returns an unlock function. The
// returned closure is idempotent — calling it twice is safe — so callers can
// `defer unlock()` after early-return branches.
func (l *fsPathLocker) lock(path string) func() {
	pm := l.stripe(path)
	pm.Lock()
	var once sync.Once
	return func() {
		once.Do(func() { pm.Unlock() })
	}
}

// size reports the fixed stripe count; the locker never grows beyond it.
func (l *fsPathLocker) size() int {
	return len(l.stripes)
}

func lockKeyForTest(path string) string {
	return normalizeLockKey(path)
}

var fsPathMu = newFsPathLocker()
