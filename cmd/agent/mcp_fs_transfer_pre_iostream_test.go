package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// fs.transfer 的 pre-IOStream 早退路径必须经过 attach 后用 NZTE 显式上报，
// 否则 dashboard 的 openFsTransferStream 会在 WaitForAgent 等到 30s 才超时。
// 这里把 pre-IOStream 决策拆成 decideFsTransferEarlyError 单独测：实现层
// 必须在拨号成功后总是发 hello + 发 NZTE，但决策本身是纯函数，便于在
// 不依赖真实 gRPC 通道的前提下钉死契约。

func mustTaskData(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestDecideFsTransferEarlyError_DisableCommandExecute(t *testing.T) {
	cfg := model.AgentConfig{DisableCommandExecute: true}
	task := &pb.Task{Data: mustTaskData(t, model.FsTransferRequest{
		StreamID: "sid-1",
		Op:       model.MCPFsTransferOpUpload,
		Path:     "/tmp/x",
	})}

	req, msg, hasStream := decideFsTransferEarlyError(cfg.DisableCommandExecute, task)
	if msg == "" {
		t.Fatal("DisableCommandExecute must produce an early error message")
	}
	if !strings.Contains(strings.ToLower(msg), "disable") {
		t.Errorf("error must mention DisableCommandExecute for operator visibility, got %q", msg)
	}
	// stream_id 已知 → 必须仍走 attach 路径，让 dashboard 收到 NZTE，而不是
	// 静默 return。
	if !hasStream {
		t.Fatal("DisableCommandExecute path must still attach so dashboard receives NZTE")
	}
	if req == nil || req.StreamID != "sid-1" {
		t.Fatalf("decode must yield streamId for hello frame; got req=%+v", req)
	}
}

func TestDecideFsTransferEarlyError_BadJSON(t *testing.T) {
	cfg := model.AgentConfig{}
	task := &pb.Task{Data: "{not-json"}

	req, msg, hasStream := decideFsTransferEarlyError(cfg.DisableCommandExecute, task)
	if msg == "" {
		t.Fatal("malformed JSON must produce an early error message")
	}
	if hasStream {
		t.Fatal("without a parseable stream_id we cannot attach; hasStream must be false")
	}
	if req != nil {
		t.Fatalf("bad JSON must not yield a request; got %+v", req)
	}
}

func TestDecideFsTransferEarlyError_MissingStreamID(t *testing.T) {
	cfg := model.AgentConfig{}
	task := &pb.Task{Data: mustTaskData(t, model.FsTransferRequest{
		StreamID: "",
		Op:       model.MCPFsTransferOpUpload,
		Path:     "/tmp/x",
	})}

	req, msg, hasStream := decideFsTransferEarlyError(cfg.DisableCommandExecute, task)
	if msg == "" {
		t.Fatal("missing stream_id must produce an early error message")
	}
	if hasStream {
		t.Fatal("no stream_id means no IOStream hello possible; hasStream must be false")
	}
	if req == nil {
		t.Fatal("decoded request must be returned for diagnostics even when stream_id missing")
	}
}

func TestDecideFsTransferEarlyError_MissingPath(t *testing.T) {
	cfg := model.AgentConfig{}
	task := &pb.Task{Data: mustTaskData(t, model.FsTransferRequest{
		StreamID: "sid-2",
		Op:       model.MCPFsTransferOpDownload,
		Path:     "",
	})}

	req, msg, hasStream := decideFsTransferEarlyError(cfg.DisableCommandExecute, task)
	if msg == "" {
		t.Fatal("missing path must produce an early error message")
	}
	if !hasStream {
		t.Fatal("with a valid stream_id we must still attach + send NZTE")
	}
	if req == nil || req.StreamID != "sid-2" {
		t.Fatalf("decode must yield streamId for hello frame; got req=%+v", req)
	}
}

func TestDecideFsTransferEarlyError_UnknownOp(t *testing.T) {
	cfg := model.AgentConfig{}
	task := &pb.Task{Data: mustTaskData(t, model.FsTransferRequest{
		StreamID: "sid-3",
		Op:       "weird-op",
		Path:     "/tmp/x",
	})}

	req, msg, hasStream := decideFsTransferEarlyError(cfg.DisableCommandExecute, task)
	if msg == "" {
		t.Fatal("unknown op must be flagged at the pre-IOStream stage")
	}
	if !hasStream {
		t.Fatal("unknown op with a valid stream_id must still attach for NZTE")
	}
	if req == nil || req.StreamID != "sid-3" {
		t.Fatalf("decode must yield streamId for hello frame; got req=%+v", req)
	}
}

func TestDecideFsTransferEarlyError_HappyPathNoError(t *testing.T) {
	cfg := model.AgentConfig{}
	task := &pb.Task{Data: mustTaskData(t, model.FsTransferRequest{
		StreamID: "sid-ok",
		Op:       model.MCPFsTransferOpUpload,
		Path:     "/tmp/file",
	})}

	req, msg, hasStream := decideFsTransferEarlyError(cfg.DisableCommandExecute, task)
	if msg != "" {
		t.Fatalf("happy path must not produce an early error; got %q", msg)
	}
	if !hasStream {
		t.Fatal("happy path must indicate hasStream=true")
	}
	if req == nil || req.StreamID != "sid-ok" || req.Op != model.MCPFsTransferOpUpload || req.Path != "/tmp/file" {
		t.Fatalf("happy path must echo decoded request; got %+v", req)
	}
}
