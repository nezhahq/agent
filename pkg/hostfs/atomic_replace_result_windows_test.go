//go:build windows

package hostfs

import (
	"errors"
	"testing"
)

func assertDefaultAtomicReplaceResult(t *testing.T, result AtomicReplaceResult, err error) {
	t.Helper()
	if !result.Committed || result.Durability != DurabilityUnknown {
		t.Fatalf("result = %+v, want committed with unknown durability", result)
	}
	if !errors.Is(err, ErrCommittedDurabilityUnknown) {
		t.Fatalf("AtomicReplace() error = %v, want ErrCommittedDurabilityUnknown", err)
	}
	var durabilityErr *CommittedDurabilityUnknown
	if !errors.As(err, &durabilityErr) {
		t.Fatalf("AtomicReplace() error = %T %v, want *CommittedDurabilityUnknown", err, err)
	}
}
