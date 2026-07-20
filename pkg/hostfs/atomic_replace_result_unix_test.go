//go:build unix

package hostfs

import "testing"

func assertDefaultAtomicReplaceResult(t *testing.T, result AtomicReplaceResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("AtomicReplace(): %v", err)
	}
	if !result.Committed || result.Durability != DurabilityConfirmed {
		t.Fatalf("result = %+v, want committed with confirmed durability", result)
	}
}
