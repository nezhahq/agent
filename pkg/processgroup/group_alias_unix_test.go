//go:build unix && !aix

package processgroup

import "testing"

// procExitGroupForTest normalizes the value-vs-pointer return of
// NewProcessExitGroup so cross-platform tests can hold a single *ProcessExitGroup.
// unix returns a value; take its address.
type procExitGroupForTest = *ProcessExitGroup

func newProcExitGroupForTest(t *testing.T) procExitGroupForTest {
	t.Helper()
	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	return &pg
}
