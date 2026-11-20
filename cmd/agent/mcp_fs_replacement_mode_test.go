package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func writeThroughFsWrite(t *testing.T, req model.FsWriteRequest) {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var res pb.TaskResult
	handleFsWriteTask(&pb.Task{Type: model.TaskTypeFsWrite, Data: string(body)}, &res)
	var out model.FsWriteResult
	unmarshalResult(t, &res, &out)
	if out.Error != "" {
		t.Fatalf("fs.write failed: %s", out.Error)
	}
}

func requireFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode of %s = %o, want %o", filepath.Base(path), got, want)
	}
}

func createPrivateFile(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not representable on Windows")
	}
	path := filepath.Join(t.TempDir(), "private.key")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Editing a 0600 secret must not publish it: without an explicit mode the
// replacement keeps the permission bits of the file it replaces.
func TestFsWrite_KeepsPermissionsOfReplacedFile(t *testing.T) {
	path := createPrivateFile(t)

	writeThroughFsWrite(t, model.FsWriteRequest{Path: path, Content: "new", Encoding: "utf8"})

	requireFileMode(t, path, 0o600)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new" {
		t.Fatalf("content = %q, err = %v", data, err)
	}
}

func TestFsWrite_ExplicitModeOverridesReplacedFile(t *testing.T) {
	path := createPrivateFile(t)

	writeThroughFsWrite(t, model.FsWriteRequest{Path: path, Content: "new", Encoding: "utf8", Mode: "640"})

	requireFileMode(t, path, 0o640)
}

func TestFsWrite_NewFileDefaultsTo0644(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not representable on Windows")
	}
	path := filepath.Join(t.TempDir(), "created.txt")

	writeThroughFsWrite(t, model.FsWriteRequest{Path: path, Content: "new", Encoding: "utf8"})

	requireFileMode(t, path, 0o644)
}

func TestFsTransferUpload_KeepsPermissionsOfReplacedFile(t *testing.T) {
	path := createPrivateFile(t)
	stream := &blockingRecvStream{
		release: make(chan struct{}),
		recvHit: make(chan struct{}),
		payload: []byte("new"),
	}
	close(stream.release)

	fsTransferUpload(stream, &model.FsTransferRequest{
		Op:   model.MCPFsTransferOpUpload,
		Path: path,
		Size: int64(len(stream.payload)),
	})

	requireFileMode(t, path, 0o600)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new" {
		t.Fatalf("content = %q, err = %v", data, err)
	}
}
