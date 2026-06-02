package processgroup

import "testing"

// Empty-group lifecycle contract, locked identically on Linux, macOS and
// Windows: a group with no AddProcess must survive every cleanup entry point
// without panicking, Dispose() must finalize the group (IsClosed) and every
// API must be idempotent so the caller's defer Close()/Dispose() pairing in
// mcp_handlers can fire on any path.
func TestProcessExitGroup_EmptyLifecycleIsIdempotent(t *testing.T) {
	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	if pg.IsClosed() {
		t.Fatal("freshly created group must not be closed")
	}

	pg.ReapDescendants()
	if pg.IsClosed() {
		t.Fatal("ReapDescendants on a live empty group must not mark it closed")
	}

	if err := pg.Dispose(); err != nil {
		t.Fatalf("Dispose on empty group must return nil, got %v", err)
	}
	if !pg.IsClosed() {
		t.Fatal("Dispose must finalize the group so IsClosed() reports released, matching Windows")
	}

	if err := pg.Dispose(); err != nil {
		t.Fatalf("Dispose after Dispose must stay nil, got %v", err)
	}
	pg.ReapDescendants()
	pg.Close()
	pg.Close()
}

// AddProcess on a closed group must be refused on every platform so a caller
// cannot register a process against released kernel resources (Windows job +
// proc handles, unix stale pgids). The error must be the shared sentinel.
func TestProcessExitGroup_AddProcessOnClosedGroupIsRejected(t *testing.T) {
	pg, err := NewProcessExitGroup()
	if err != nil {
		t.Fatalf("NewProcessExitGroup: %v", err)
	}
	pg.Close()

	if err := pg.AddProcess(nil); err != errProcessExitGroupClosed {
		t.Fatalf("AddProcess on closed group must return errProcessExitGroupClosed, got %v", err)
	}
}
