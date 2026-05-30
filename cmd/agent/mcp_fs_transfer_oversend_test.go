package main

import (
	"strings"
	"testing"
)

// M6 regression: when a single inbound IOStreamData payload exceeds the
// declared remaining bytes, agent must NOT silently truncate and write
// the prefix. The pre-fix behaviour hid protocol violation and could
// mask corruption / desync. enforceUploadOversend is the gate.
func TestEnforceUploadOversend_RejectsPayloadLargerThanRemaining(t *testing.T) {
	got, err := enforceUploadOversend([]byte("0123456789"), 4)
	if err == nil {
		t.Fatal("oversend must be rejected; got nil error")
	}
	if got != nil {
		t.Fatalf("returned payload must be nil on rejection, got %q", string(got))
	}
	if !strings.Contains(err.Error(), "oversend") {
		t.Fatalf("error must mention oversend, got %v", err)
	}
}

func TestEnforceUploadOversend_AllowsPayloadEqualToRemaining(t *testing.T) {
	got, err := enforceUploadOversend([]byte("abcd"), 4)
	if err != nil {
		t.Fatalf("payload == remaining must pass, got %v", err)
	}
	if string(got) != "abcd" {
		t.Fatalf("payload must pass through unchanged, got %q", string(got))
	}
}

func TestEnforceUploadOversend_AllowsPayloadSmallerThanRemaining(t *testing.T) {
	got, err := enforceUploadOversend([]byte("ab"), 10)
	if err != nil {
		t.Fatalf("payload < remaining must pass, got %v", err)
	}
	if string(got) != "ab" {
		t.Fatalf("payload must pass through unchanged, got %q", string(got))
	}
}

func TestEnforceUploadOversend_RejectsEvenOneByteOver(t *testing.T) {
	_, err := enforceUploadOversend([]byte("12345"), 4)
	if err == nil {
		t.Fatal("even a single oversend byte must be rejected — protocol invariant")
	}
}
