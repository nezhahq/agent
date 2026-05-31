package main

import (
	"strings"
	"testing"
)

// M11 regression: Windows alternate data streams (ADS) addressed via
// `C:\file:stream`, `C:\:stream`, `\\?\C:\file:stream`, UNC extended
// variants, etc. must NOT be acceptable fs paths. The root guard treats
// them as ordinary paths because they don't match the `C:\` shape, but
// the ADS suffix lets MCP writes target metadata sidecars rather than
// the visible file contents — a clear violation of the intended
// "filesystem path = file or directory" contract.
func TestHasWindowsADSSuffix_RejectsObviousADS(t *testing.T) {
	cases := []string{
		`C:\file.txt:hidden`,
		`c:\dir\file:stream`,
		`\\?\C:\file:stream`,
		`\\srv\share\file:stream`,
		`C:\:stream`,
		`X:\foo\bar.exe:Zone.Identifier`,
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if !hasWindowsADSSuffix(p) {
				t.Fatalf("path with ADS suffix must be detected: %q", p)
			}
		})
	}
}

// NT device-namespace paths (\\?\GLOBALROOT\Device\..., \\.\C:\...) reach
// the same NTFS final-name parser, so an ADS suffix on them is just as
// effective at targeting a metadata sidecar. The guard must catch them too,
// not fall through its else-branch to "not Windows-shaped".
func TestHasWindowsADSSuffix_RejectsDeviceNamespaceADS(t *testing.T) {
	cases := []string{
		`\\?\GLOBALROOT\Device\HarddiskVolume3\Users\Public\victim.txt:evil`,
		`\\.\C:\Users\Public\victim.txt:evil`,
		`\\?\Volume{12345678-1234-1234-1234-123456789abc}\file.txt:stream`,
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if !hasWindowsADSSuffix(p) {
				t.Fatalf("device-namespace ADS path must be detected: %q", p)
			}
		})
	}
}

// Device-namespace paths WITHOUT an ADS suffix must still be accepted, so the
// fix above does not over-reject legitimate volume paths.
func TestHasWindowsADSSuffix_AcceptsDeviceNamespaceNonADS(t *testing.T) {
	cases := []string{
		`\\?\GLOBALROOT\Device\HarddiskVolume3\Users\Public\victim.txt`,
		`\\.\C:\Users\Public\victim.txt`,
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if hasWindowsADSSuffix(p) {
				t.Fatalf("device-namespace non-ADS path must not be flagged: %q", p)
			}
		})
	}
}

func TestHasWindowsADSSuffix_AcceptsNormalPaths(t *testing.T) {
	cases := []string{
		`C:\`,
		`C:\file.txt`,
		`C:\dir\subdir\file.txt`,
		`\\srv\share\file.txt`,
		`\\?\C:\file.txt`,
		`/etc/passwd`,
		`/var/log/messages`,
		``,
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			if hasWindowsADSSuffix(p) {
				t.Fatalf("normal path must not be flagged as ADS: %q", p)
			}
		})
	}
}

// resolveFsPath must reject ADS for any platform — the dashboard might
// produce Windows-shaped paths even on a Linux agent if the LLM is
// operator-typed, and we don't want a Linux agent silently writing to a
// literal `:stream`-suffixed file (which is legal on POSIX but breaks
// the cross-platform invariant).
func TestResolveFsPath_RejectsWindowsADS(t *testing.T) {
	_, err := resolveFsPath(`C:\file:stream`)
	if err == nil {
		t.Fatal("resolveFsPath must reject Windows ADS paths regardless of GOOS")
	}
	if !strings.Contains(err.Error(), "alternate data stream") &&
		!strings.Contains(err.Error(), "ADS") {
		t.Fatalf("error must mention ADS, got %v", err)
	}
}
