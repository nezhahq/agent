package main

import (
	"errors"
	"path/filepath"
	"strings"
)

// refuseFsTransferUploadAtRoot is the writer-side wrapper around
// isFilesystemRoot. Both fs.write and fs.transfer upload paths run
// os.MkdirAll(filepath.Dir(clean)) and then os.Rename(tmp, clean); when
// clean is a filesystem root those calls degrade to creating temp files
// inside `/` and attempting to rename a regular file over the root mount
// point — at best a noisy error, at worst a partial wipe of root-owned
// metadata on permissive setups. We refuse at the handler boundary so
// the same contract applies to delete, write, and transfer.
func refuseFsTransferUploadAtRoot(clean string) error {
	if isFilesystemRoot(clean) {
		return errors.New("refusing to write to filesystem root")
	}
	return nil
}

// isFilesystemRoot reports whether p designates the top of a filesystem
// volume on any supported GOOS. The agent's recursive fs.delete path runs
// os.RemoveAll, so a permissive root guard turns one MCP call into a wipe
// of the whole disk / share. We enforce the check by *path shape* rather
// than GOOS — the same agent binary may receive paths produced on a
// different OS by a remote LLM client, and filepath.VolumeName is
// GOOS-gated and therefore unreliable for that case.
//
// Recognised roots:
//   - POSIX root: "/" or "".
//   - Windows drive root: a single ASCII letter, a colon, and a single
//     directory separator (forward or back slash), e.g. `C:\`, `c:/`.
//   - UNC share root: `\\host\share` or `\\host\share\` with no further
//     path component.
//   - Any path that equals its own parent. filepath.Dir is reflexive on
//     roots on every OS, so this is a portable last-resort check.
func isFilesystemRoot(p string) bool {
	if p == "" || p == "/" {
		return true
	}

	// Collapse the extended-length / device prefix so `\\?\C:\` and
	// `\\?\UNC\srv\share` are recognised as the same roots as `C:\` and
	// `\\srv\share`. `\\?\UNC\` maps back to the `\\` UNC form; `\\?\X:\`
	// maps back to the drive-root form `X:\`. (The separator matters: bare
	// `X:` is the drive-relative current directory, not the volume root, so
	// it is intentionally NOT treated as a root below.) Windows treats the
	// `\`-terminated forms as identical volume roots, so a recursive delete
	// on either wipes the volume.
	if rest, ok := strings.CutPrefix(p, `\\?\`); ok {
		if unc, isUNC := cutUNCExtendedPrefix(rest); isUNC {
			p = `\\` + unc
		} else {
			p = rest
		}
	}

	// Windows drive root: `X:\`, `X:/`. filepath.Clean keeps the trailing
	// separator on drive roots, so the length is exactly 3.
	if len(p) == 3 && p[1] == ':' && isASCIIAlpha(p[0]) && isPathSep(p[2]) {
		return true
	}

	// UNC: must start with two backslashes, have exactly host and share
	// segments, and no further path component.
	if strings.HasPrefix(p, `\\`) {
		// Strip a single trailing separator before counting segments so
		// `\\srv\share` and `\\srv\share\` are both detected.
		trimmed := strings.TrimRight(p, `\/`)
		// After trim the body is `\\srv\share`. Split on backslash.
		// Expected pieces: "", "", "srv", "share" — len 4 — with no
		// further non-empty pieces.
		parts := strings.Split(trimmed, `\`)
		if len(parts) == 4 && parts[0] == "" && parts[1] == "" && parts[2] != "" && parts[3] != "" {
			return true
		}
	}

	// Reflexive parent: any root satisfies filepath.Dir(p) == p on its
	// home GOOS. Cheap defence-in-depth for filesystems we may not have
	// thought of yet (plan9 "/n/.", etc.).
	if filepath.Dir(p) == p {
		return true
	}

	return false
}

// cutUNCExtendedPrefix strips a case-insensitive `UNC\` segment from the
// body of a `\\?\` path and reports whether it was present, so the caller
// can rebuild the canonical `\\host\share` form.
func cutUNCExtendedPrefix(rest string) (string, bool) {
	if len(rest) < 4 || !strings.EqualFold(rest[:4], `UNC\`) {
		return rest, false
	}
	return rest[4:], true
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func isPathSep(b byte) bool {
	return b == '/' || b == '\\'
}

// hasWindowsADSSuffix detects paths that target an NTFS Alternate Data
// Stream (`C:\file:stream`, `\\srv\share\file:stream`, `\\?\C:\file:stream`,
// even `C:\:stream`). The shape is: after any drive letter or volume
// prefix (`C:`, `\\?\C:`, `\\?\UNC\srv\share`, `\\srv\share`) some path
// component contains an embedded `:`.
//
// Detected at the agent boundary regardless of GOOS — the same agent
// binary may receive Windows-shaped paths from an LLM client even when
// running on Linux. Letting ADS through means MCP writes can target file
// metadata sidecars rather than visible contents, breaking the
// "filesystem path = file or directory" contract callers assume.
func hasWindowsADSSuffix(p string) bool {
	if p == "" {
		return false
	}
	rest := p
	// Strip extended-path prefix `\\?\` once so the volume scan below
	// can examine the underlying drive / UNC form uniformly.
	if strings.HasPrefix(rest, `\\?\`) {
		rest = rest[4:]
		if strings.HasPrefix(strings.ToUpper(rest), `UNC\`) {
			rest = rest[4:]
			rest = stripUNCHostShare(rest)
		} else if len(rest) >= 2 && rest[1] == ':' && isASCIIAlpha(rest[0]) {
			rest = rest[2:]
		}
	} else if strings.HasPrefix(rest, `\\`) {
		rest = stripUNCHostShare(rest[2:])
	} else if len(rest) >= 2 && rest[1] == ':' && isASCIIAlpha(rest[0]) {
		rest = rest[2:]
	} else {
		return false
	}
	// Any component-internal `:` after the volume prefix means ADS.
	// `C:\` (rest="\\") and `C:\file.txt` (rest="\file.txt") have no `:`.
	// `C:\file:stream` (rest="\file:stream") matches.
	return strings.ContainsRune(rest, ':')
}

// stripUNCHostShare consumes `host\share` or `host/share` (with optional
// trailing separator) from the start of s and returns the remainder.
// Returns an empty string when the input does not actually carry both
// host and share segments — caller treats that as "not a parseable UNC"
// so the ADS scan falls through to no-match.
func stripUNCHostShare(s string) string {
	parts := strings.SplitN(strings.ReplaceAll(s, "/", `\`), `\`, 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	if len(parts) == 2 {
		return ""
	}
	return `\` + parts[2]
}
