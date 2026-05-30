package main

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
)

// M9 regression: agent error envelopes returned to the dashboard MUST
// NOT leak internal paths, temp file names, or raw OS error strings.
// sanitizeFsError maps the structured error class to a stable public
// short string; raw context only ever survives in audit logs.
func TestSanitizeFsError_PathNotExist(t *testing.T) {
	raw := &fs.PathError{Op: "open", Path: "/root/secret/data.db", Err: fs.ErrNotExist}
	code, msg := sanitizeFsError(raw)
	if code != "fs_not_found" {
		t.Fatalf("code=%q want fs_not_found", code)
	}
	if strings.Contains(msg, "/root/secret") || strings.Contains(msg, "data.db") {
		t.Fatalf("sanitised message must not include the raw path, got %q", msg)
	}
}

func TestSanitizeFsError_PermissionDenied(t *testing.T) {
	raw := &fs.PathError{Op: "open", Path: "/etc/shadow", Err: fs.ErrPermission}
	code, msg := sanitizeFsError(raw)
	if code != "fs_permission_denied" {
		t.Fatalf("code=%q want fs_permission_denied", code)
	}
	if strings.Contains(msg, "/etc/shadow") {
		t.Fatalf("sanitised message must not include the raw path, got %q", msg)
	}
}

func TestSanitizeFsError_NotRegularFile(t *testing.T) {
	raw := errors.New("path is not a regular file")
	code, _ := sanitizeFsError(raw)
	if code != "fs_not_regular_file" {
		t.Fatalf("code=%q want fs_not_regular_file", code)
	}
}

func TestSanitizeFsError_IfMatchConflict(t *testing.T) {
	raw := errors.New("if_match precondition failed: sha256 mismatch")
	code, _ := sanitizeFsError(raw)
	if code != "fs_conflict" {
		t.Fatalf("code=%q want fs_conflict", code)
	}
}

func TestSanitizeFsError_UnknownDefaultsToInternal(t *testing.T) {
	raw := errors.New("some weird internal kernel string with /tmp/private-77af path leak")
	code, msg := sanitizeFsError(raw)
	if code != "fs_internal" {
		t.Fatalf("code=%q want fs_internal", code)
	}
	if strings.Contains(msg, "/tmp/private-77af") {
		t.Fatalf("sanitised message must not echo unknown errors verbatim, got %q", msg)
	}
}

func TestSanitizeFsError_NilReturnsEmpty(t *testing.T) {
	code, msg := sanitizeFsError(nil)
	if code != "" || msg != "" {
		t.Fatalf("nil error must return empty code/msg, got code=%q msg=%q", code, msg)
	}
}

func TestFsErrMsg_StripsRawPath(t *testing.T) {
	raw := &fs.PathError{Op: "rename", Path: "/root/.ssh/.mcp-write-123", Err: fs.ErrPermission}
	msg := fsErrMsg(raw)
	if strings.Contains(msg, "/root/.ssh") || strings.Contains(msg, ".mcp-write-123") {
		t.Fatalf("fsErrMsg must not leak the raw path/temp name, got %q", msg)
	}
	if msg == "" {
		t.Fatal("fsErrMsg must return a non-empty client message")
	}
}

func TestSanitizeFsError_InvalidPathMessagesArePreserved(t *testing.T) {
	for _, raw := range []string{"path required", "path must be absolute"} {
		code, msg := sanitizeFsError(errors.New(raw))
		if code != "fs_invalid_path" {
			t.Fatalf("%q: code=%q want fs_invalid_path (must not collapse to internal)", raw, code)
		}
		if msg == "internal agent error" {
			t.Fatalf("%q: input-validation error must keep an actionable message, not %q", raw, msg)
		}
	}
}
