package main

import (
	"errors"
	"io/fs"
	"strings"
)

// sanitizeFsError maps a raw agent-side error into a stable public
// (code, message) pair so dashboard responses do not leak internal
// paths, temp file names, or platform error verbatim. Audit logs keep
// the raw text via writeTransferFailureAudit / mcpAuditWrite; only the
// client-visible envelope is sanitised.
//
// Codes are intentionally small and stable so SIEM / clients can branch
// on them. The default branch fails closed: unknown errors map to a
// generic "internal" code and a fixed message, never the raw string.
func sanitizeFsError(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "fs_not_found", "file or directory does not exist"
	case errors.Is(err, fs.ErrPermission):
		return "fs_permission_denied", "permission denied"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "if_match precondition failed"):
		return "fs_conflict", "if_match precondition failed"
	case strings.Contains(msg, "is not a regular file"):
		return "fs_not_regular_file", "path is not a regular file"
	case strings.Contains(msg, "alternate data stream"):
		return "fs_invalid_path", "path is not supported"
	case strings.Contains(msg, "refusing to write to filesystem root"):
		return "fs_invalid_path", "path targets a filesystem root"
	case msg == "path required":
		return "fs_invalid_path", "path required"
	case msg == "path must be absolute":
		return "fs_invalid_path", "path must be absolute"
	}
	return "fs_internal", "internal agent error"
}

// fsErrMsg returns only the sanitised, client-safe message for an FS error.
func fsErrMsg(err error) string {
	_, msg := sanitizeFsError(err)
	return msg
}

// execErrMsg sanitises an exec setup/run error before it reaches the
// client-visible ExecResult.Error, matching fsErrMsg's fail-closed policy.
// Raw errors here (cmd.Start, pipe/job-object setup, chdir) embed absolute
// paths, the resolved executable, cwd, and platform API detail; audit logs
// retain the raw text, the client only sees a stable category.
func execErrMsg(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "command or working directory not found"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "executable file not found"):
		return "executable file not found"
	case strings.Contains(msg, "cmd.Wait pinned"):
		return "process did not exit after kill"
	}
	return "internal agent error"
}
