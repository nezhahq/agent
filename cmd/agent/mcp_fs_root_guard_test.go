package main

import (
	"encoding/json"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// TestIsFilesystemRootRejectsVolumeRoots is the red-bar test for the
// fs.delete root guard. The shipped guard at mcp_handlers.go only rejects
// "/" and the empty string, so Windows / UNC volume roots like `C:\` and
// `\\srv\share` slip through and reach os.RemoveAll. We pin the cross-
// platform set of roots that MUST be refused regardless of GOOS, so an LLM
// driving a Windows agent cannot recursively wipe a drive or share.
func TestIsFilesystemRootRejectsVolumeRoots(t *testing.T) {
	t.Parallel()

	// Each case is the *cleaned, absolute* path that resolveFsPath would
	// produce. We feed both POSIX and Windows-style separators because
	// filepath.Clean preserves them per-GOOS and the agent may run on
	// either. The guard must be path-shape based, not GOOS based.
	cases := []string{
		// POSIX root.
		"/",
		// Windows drive roots — both separator styles a client might send.
		`C:\`,
		`c:\`,
		`Z:\`,
		"C:/",
		// UNC share roots.
		`\\server\share`,
		`\\server\share\`,
		// Extended-length / device UNC share roots. Windows accepts
		// `\\?\UNC\server\share` as the very same share root as
		// `\\server\share`, so a recursive delete there wipes the whole
		// share. The guard must collapse the `\\?\UNC\` prefix before
		// counting host/share segments.
		`\\?\UNC\server\share`,
		`\\?\UNC\server\share\`,
		`\\?\unc\server\share`,
		// Extended-length drive roots: `\\?\C:\` is the device-path form
		// of `C:\` and is just as destructive.
		`\\?\C:\`,
		`\\?\c:\`,
		// Defence-in-depth: any path equal to its own parent is by
		// definition a root and must never be recursively deleted.
		// (Reserved for future filesystems; cheap to enforce now.)
	}

	for _, p := range cases {
		if !isFilesystemRoot(p) {
			t.Errorf("isFilesystemRoot(%q) = false, want true (root must be refused)", p)
		}
	}
}

// TestIsFilesystemRootAllowsNonRoots is the negative companion: typical
// user-data paths must still be deletable, otherwise we just traded a
// security bug for a usability bug.
func TestIsFilesystemRootAllowsNonRoots(t *testing.T) {
	t.Parallel()

	cases := []string{
		"/tmp/foo",
		"/var/log/x.log",
		`C:\Users\alice\file.txt`,
		`C:\Users`,
		`\\server\share\dir`,
		`\\?\UNC\server\share\dir`,
		`\\?\C:\Users`,
		"/a",
	}

	for _, p := range cases {
		if isFilesystemRoot(p) {
			t.Errorf("isFilesystemRoot(%q) = true, want false (non-root must be allowed)", p)
		}
	}
}

// TestHandleFsDeleteTaskRefusesPOSIXRootRecursive pins the existing
// behaviour (refuse "/") at the handler boundary so we cannot regress
// while replacing the inline string comparison with isFilesystemRoot.
// Cross-platform roots (`C:\`, `\\srv\share`) are pinned at the helper
// level above, because resolveFsPath itself depends on GOOS and rejects
// `C:\` as non-absolute when the test host is linux.
func TestHandleFsDeleteTaskRefusesPOSIXRootRecursive(t *testing.T) {
	t.Parallel()

	req := model.FsDeleteRequest{Path: "/", Recursive: true}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	task := &pb.Task{Id: 1, Type: model.TaskTypeFsDelete, Data: string(body)}
	var res pb.TaskResult
	handleFsDeleteTask(task, &res)

	var out model.FsDeleteResult
	if err := json.Unmarshal([]byte(res.GetData()), &out); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, res.GetData())
	}
	if out.Error == "" {
		t.Fatalf("handler accepted recursive delete of POSIX root, want refusal; result=%+v", out)
	}
	if out.DeletedCount != 0 {
		t.Fatalf("DeletedCount=%d on refused root delete, want 0", out.DeletedCount)
	}
}
