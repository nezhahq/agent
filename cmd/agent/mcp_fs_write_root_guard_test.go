package main

// Pins the root guard at the fs.write entrypoint. Before this test, the
// root-check ran only inside handleFsDeleteTask, so an LLM with
// nezha:server:write could call fs.write Path="/" CreateDirs=true and
// reach os.MkdirAll("/") / os.Rename(tmpName, "/") without ever tripping
// the guard. The Rename would fail (you cannot replace `/` with a regular
// file), but it could still create a `.mcp-write-*` temp file at the root
// and on some kernels overwrite root-owned content depending on
// permissions. We refuse cleanly at the handler boundary, matching the
// fs.delete contract, before any os.* mutation runs.

import (
	"encoding/json"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestHandleFsWriteTaskRefusesPOSIXRoot(t *testing.T) {
	t.Parallel()

	req := model.FsWriteRequest{
		Path:       "/",
		Content:    "x",
		Encoding:   "utf8",
		CreateDirs: true,
	}
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	task := &pb.Task{Id: 1, Type: model.TaskTypeFsWrite, Data: string(body)}
	var res pb.TaskResult
	handleFsWriteTask(task, &res)

	var out model.FsWriteResult
	if err := json.Unmarshal([]byte(res.GetData()), &out); err != nil {
		t.Fatalf("unmarshal: %v\nraw: %s", err, res.GetData())
	}
	if out.Error == "" {
		t.Fatalf("handler accepted fs.write to POSIX root, want refusal; result=%+v", out)
	}
}
