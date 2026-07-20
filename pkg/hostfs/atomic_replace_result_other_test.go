//go:build !unix && !windows

package hostfs

import "testing"

func assertDefaultAtomicReplaceResult(t *testing.T, result AtomicReplaceResult, err error) {
	t.Helper()
	t.Fatalf("AtomicReplace() unexpectedly reached default result on unsupported platform: result=%+v error=%v", result, err)
}
