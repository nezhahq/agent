package hostfs

import (
	"errors"
	"testing"
)

func TestJoinFinalCleanup_preserves_primary_and_close_errors(t *testing.T) {
	t.Parallel()

	primaryErr := errors.New("native operation failed")
	closeErr := errors.New("native close failed")

	got := joinFinalCleanup(primaryErr, func() error { return closeErr })

	if !errors.Is(got, primaryErr) {
		t.Fatalf("error = %v, want primary error", got)
	}
	if !errors.Is(got, closeErr) {
		t.Fatalf("error = %v, want close error", got)
	}
}

func TestJoinFinalCleanup_returns_close_error_without_primary(t *testing.T) {
	t.Parallel()

	closeErr := errors.New("native close failed")

	got := joinFinalCleanup(nil, func() error { return closeErr })

	if !errors.Is(got, closeErr) {
		t.Fatalf("error = %v, want close error", got)
	}
}
