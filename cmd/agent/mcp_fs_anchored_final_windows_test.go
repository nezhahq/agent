//go:build windows

package main

import (
	"errors"
	"testing"

	"github.com/nezhahq/agent/pkg/hostfs"
)

func TestAnchoredRejectsFinal_windows_reparse_point(t *testing.T) {
	fixture := newSpecialFileFixture(t)
	if fixture.ReparseCapabilityError != nil {
		t.Fatalf("[blocked: native reparse capability] %v", fixture.ReparseCapabilityError)
	}
	anchor, err := hostfs.New(fixture.ReparsePath)
	if err != nil {
		t.Fatalf("New(reparse): %v", err)
	}
	defer func() { _ = anchor.Close() }()

	file, err := anchor.OpenDirectory()
	if file != nil {
		_ = file.Close()
		t.Fatalf("OpenDirectory(reparse) file = %#v, want nil", file)
	}
	var typeErr *hostfs.FinalTargetTypeError
	if !errors.As(err, &typeErr) {
		t.Fatalf("error type = %T (%v), want *FinalTargetTypeError", err, err)
	}
	if typeErr.Actual != hostfs.FinalTargetSymlinkReparse {
		t.Fatalf("actual type = %v, want %v", typeErr.Actual, hostfs.FinalTargetSymlinkReparse)
	}
}
