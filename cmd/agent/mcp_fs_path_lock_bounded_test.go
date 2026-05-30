package main

import (
	"fmt"
	"testing"
)

// The path locker must not grow without bound: a remote caller hitting many
// distinct paths used to insert one permanent map entry per path. A striped
// locker keeps a fixed number of mutexes regardless of how many unique paths
// are locked.
func TestFsPathLocker_IsBounded(t *testing.T) {
	l := newFsPathLocker()
	for i := 0; i < 100000; i++ {
		unlock := l.lock(fmt.Sprintf("/tmp/unique/path/%d", i))
		unlock()
	}
	if got := l.size(); got > fsPathLockStripes {
		t.Fatalf("locker retained %d entries; must stay bounded by %d stripes", got, fsPathLockStripes)
	}
}

// Two paths in different stripes must both be holdable at once without
// deadlock. Pick paths whose stripes differ so the assertion is meaningful.
func TestFsPathLocker_DistinctStripesDoNotDeadlock(t *testing.T) {
	l := newFsPathLocker()
	a := "/tmp/a"
	var b string
	for i := 0; ; i++ {
		b = fmt.Sprintf("/tmp/b%d", i)
		if l.stripe(a) != l.stripe(b) {
			break
		}
	}
	u1 := l.lock(a)
	u2 := l.lock(b)
	u2()
	u1()
}
