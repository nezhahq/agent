//go:build windows

package processgroup

import (
	"testing"

	"golang.org/x/sys/windows"
)

// Dispose() is called synchronously from the MCP exec timeout branch. If the
// post-terminate wait is INFINITE, a wedged JobObject signal hangs the whole
// timeout handler. Guard against a regression back to windows.INFINITE.
func TestDisposeJobWaitTimeoutIsBounded(t *testing.T) {
	if disposeJobWaitTimeoutMs == windows.INFINITE {
		t.Fatal("Dispose must use a bounded WaitForSingleObject timeout, not INFINITE")
	}
	if disposeJobWaitTimeoutMs <= 0 {
		t.Fatalf("dispose wait timeout must be positive and finite, got %d", disposeJobWaitTimeoutMs)
	}
}
