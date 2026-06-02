//go:build windows

package processgroup

import "testing"

// procExitGroupForTest normalizes the value-vs-pointer return of
// NewProcessExitGroup so cross-platform tests can hold a single *ProcessExitGroup.
// Windows already returns a pointer.
type procExitGroupForTest = *ProcessExitGroup

func newProcExitGroupForTest(t *testing.T) procExitGroupForTest {
	t.Helper()
	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	return pg
}
