package main

import (
	"fmt"
	"testing"
)

// The path locker must retain exactly its fixed stripe array even after a
// remote caller locks many unique paths.
func TestFsPathLocker_RetainsExactlyFixedStripesAfterManyPaths(t *testing.T) {
	// Given
	locker := newFsPathLocker()
	const pathCount = 100000

	// When
	for pathIndex := range pathCount {
		unlock := locker.lock(fmt.Sprintf("/tmp/unique/path/%d", pathIndex))
		unlock()
	}

	// Then
	if got := locker.size(); got != 1024 {
		t.Fatalf("locker retained %d entries; want exactly 1024 stripes", got)
	}
}
