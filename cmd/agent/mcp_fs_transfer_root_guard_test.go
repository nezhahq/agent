package main

// Pins the root guard at the fs.transfer entrypoint. Without this, an LLM
// with nezha:server:write could call fs.upload_url with Path="/" and reach
// os.MkdirAll("/") / os.CreateTemp("/", ...) / os.Rename(tmpName, "/")
// inside fsTransferUpload before any check. We refuse before any fs
// mutation runs, matching the fs.delete / fs.write contract.
//
// The check itself is path-shape based; we test it through the validator
// to keep the test free of the IOStream / gRPC stream the real handler
// requires.

import "testing"

func TestRefuseFsTransferUploadAtRootRefusesRoots(t *testing.T) {
	t.Parallel()

	cases := []string{
		"/",
		`C:\`,
		`\\server\share`,
	}

	for _, p := range cases {
		err := refuseFsTransferUploadAtRoot(p)
		if err == nil {
			t.Errorf("refuseFsTransferUploadAtRoot(%q) = nil, want refusal", p)
		}
	}
}

func TestRefuseFsTransferUploadAtRootAllowsRegularFile(t *testing.T) {
	t.Parallel()

	cases := []string{
		"/tmp/foo",
		`C:\Users\alice\file.txt`,
		`\\server\share\dir\file.bin`,
	}

	for _, p := range cases {
		if err := refuseFsTransferUploadAtRoot(p); err != nil {
			t.Errorf("refuseFsTransferUploadAtRoot(%q) = %v, want nil", p, err)
		}
	}
}
