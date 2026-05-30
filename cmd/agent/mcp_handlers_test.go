package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func init() {
	if agentConfig.UUID == "" {
		agentConfig = model.AgentConfig{}
	}
}

func unmarshalResult(t *testing.T, r *pb.TaskResult, out any) {
	t.Helper()
	if !r.GetSuccessful() {
		t.Fatalf("agent returned unsuccessful result: %s", r.GetData())
	}
	if err := json.Unmarshal([]byte(r.GetData()), out); err != nil {
		t.Fatalf("bad result json: %v\nraw: %s", err, r.GetData())
	}
}

func TestExec_BasicOK(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows; use ConPTY-aware tests instead")
	}
	req := model.ExecRequest{Cmd: "sh", Args: []string{"-c", "echo hello"}}
	body, _ := json.Marshal(req)
	task := &pb.Task{Id: 1, Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult
	handleExecTask(task, &res)
	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if out.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%s)", out.ExitCode, out.Stderr)
	}
	if !strings.Contains(out.Stdout, "hello") {
		t.Fatalf("stdout=%q", out.Stdout)
	}
}

func TestExec_NonZeroExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows")
	}
	req := model.ExecRequest{Cmd: "sh", Args: []string{"-c", "exit 7"}}
	body, _ := json.Marshal(req)
	task := &pb.Task{Id: 1, Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult
	handleExecTask(task, &res)
	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if out.ExitCode != 7 {
		t.Fatalf("expected exit 7, got %d", out.ExitCode)
	}
}

func TestExec_TimeoutKillsAndReports(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows")
	}
	req := model.ExecRequest{Cmd: "sh", Args: []string{"-c", "sleep 5"}, TimeoutSeconds: 1}
	body, _ := json.Marshal(req)
	task := &pb.Task{Id: 1, Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult
	handleExecTask(task, &res)
	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if !out.TimedOut {
		t.Fatalf("expected timed_out=true, got %+v", out)
	}
}

func TestExec_StdoutTruncated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on windows")
	}
	req := model.ExecRequest{
		Cmd:            "sh",
		Args:           []string{"-c", "yes A | head -c 200000"},
		MaxOutputBytes: 1024,
	}
	body, _ := json.Marshal(req)
	task := &pb.Task{Id: 1, Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult
	handleExecTask(task, &res)
	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if !out.StdoutTruncated {
		t.Fatalf("expected stdout_truncated=true, got len=%d", len(out.Stdout))
	}
	if len(out.Stdout) > 1024 {
		t.Fatalf("stdout exceeded cap: %d", len(out.Stdout))
	}
}

func TestExec_DisabledBlocks(t *testing.T) {
	prev := agentConfig.DisableCommandExecute
	agentConfig.DisableCommandExecute = true
	defer func() { agentConfig.DisableCommandExecute = prev }()

	req := model.ExecRequest{Cmd: "sh", Args: []string{"-c", "echo nope"}}
	body, _ := json.Marshal(req)
	task := &pb.Task{Id: 1, Type: model.TaskTypeExec, Data: string(body)}
	var res pb.TaskResult
	handleExecTask(task, &res)
	var out model.ExecResult
	unmarshalResult(t, &res, &out)
	if out.Error == "" {
		t.Fatalf("expected error when disabled")
	}
}

func TestFsList_BasicHidden(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	req := model.FsListRequest{Path: dir}
	body, _ := json.Marshal(req)
	task := &pb.Task{Id: 1, Type: model.TaskTypeFsList, Data: string(body)}
	var res pb.TaskResult
	handleFsListTask(task, &res)
	var out model.FsListResult
	unmarshalResult(t, &res, &out)
	if len(out.Entries) != 2 {
		t.Fatalf("expected 2 visible entries, got %d", len(out.Entries))
	}

	req.ShowHidden = true
	body, _ = json.Marshal(req)
	task.Data = string(body)
	res = pb.TaskResult{}
	handleFsListTask(task, &res)
	unmarshalResult(t, &res, &out)
	if len(out.Entries) != 3 {
		t.Fatalf("expected 3 entries with show_hidden, got %d", len(out.Entries))
	}
}

func TestFsList_RejectsRelativePath(t *testing.T) {
	req := model.FsListRequest{Path: "tmp"}
	body, _ := json.Marshal(req)
	task := &pb.Task{Type: model.TaskTypeFsList, Data: string(body)}
	var res pb.TaskResult
	handleFsListTask(task, &res)
	var out model.FsListResult
	_ = json.Unmarshal([]byte(res.Data), &out)
	if out.Error == "" {
		t.Fatalf("expected error for relative path")
	}
}

func TestFsRead_UTF8AndBase64(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(p, []byte{0x00, 0x41, 0xFF, 0x42}, 0o644); err != nil {
		t.Fatal(err)
	}

	req := model.FsReadRequest{Path: p, Encoding: "base64"}
	body, _ := json.Marshal(req)
	var res pb.TaskResult
	handleFsReadTask(&pb.Task{Type: model.TaskTypeFsRead, Data: string(body)}, &res)
	var out model.FsReadResult
	unmarshalResult(t, &res, &out)
	decoded, err := base64.StdEncoding.DecodeString(out.Content)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 4 || decoded[2] != 0xFF {
		t.Fatalf("base64 round-trip broke binary: %v", decoded)
	}
	sum := sha256.Sum256(decoded)
	if hex.EncodeToString(sum[:]) != out.SHA256 {
		t.Fatalf("sha256 mismatch")
	}
}

func TestFsWrite_AtomicAndSha256(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out")
	req := model.FsWriteRequest{Path: p, Content: "hello", Encoding: "utf8"}
	body, _ := json.Marshal(req)
	var res pb.TaskResult
	handleFsWriteTask(&pb.Task{Type: model.TaskTypeFsWrite, Data: string(body)}, &res)
	var out model.FsWriteResult
	unmarshalResult(t, &res, &out)

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("file content mismatch: %q", data)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != out.SHA256 {
		t.Fatalf("sha256 mismatch")
	}
}

func TestFsWrite_IfMatchOptimisticLock(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out")
	if err := os.WriteFile(p, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("v1"))
	correct := hex.EncodeToString(sum[:])

	req := model.FsWriteRequest{Path: p, Content: "v2", Encoding: "utf8", IfMatchSHA256: "deadbeef"}
	body, _ := json.Marshal(req)
	var res pb.TaskResult
	handleFsWriteTask(&pb.Task{Type: model.TaskTypeFsWrite, Data: string(body)}, &res)
	var out model.FsWriteResult
	_ = json.Unmarshal([]byte(res.Data), &out)
	if out.Error == "" {
		t.Fatalf("expected if_match failure on wrong sha")
	}
	if data, _ := os.ReadFile(p); string(data) != "v1" {
		t.Fatalf("if_match failure must leave file untouched; got %q", data)
	}

	req.IfMatchSHA256 = correct
	body, _ = json.Marshal(req)
	res = pb.TaskResult{}
	handleFsWriteTask(&pb.Task{Type: model.TaskTypeFsWrite, Data: string(body)}, &res)
	unmarshalResult(t, &res, &out)
	data, _ := os.ReadFile(p)
	if string(data) != "v2" {
		t.Fatalf("write didn't apply: %q", data)
	}
}

func TestFsDelete_FileAndDir(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	os.WriteFile(f, []byte("x"), 0o644)

	body, _ := json.Marshal(model.FsDeleteRequest{Path: f})
	var res pb.TaskResult
	handleFsDeleteTask(&pb.Task{Type: model.TaskTypeFsDelete, Data: string(body)}, &res)
	var out model.FsDeleteResult
	unmarshalResult(t, &res, &out)
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatalf("file should be gone")
	}

	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0o755)
	os.WriteFile(filepath.Join(sub, "x"), []byte("y"), 0o644)

	body, _ = json.Marshal(model.FsDeleteRequest{Path: sub})
	res = pb.TaskResult{}
	handleFsDeleteTask(&pb.Task{Type: model.TaskTypeFsDelete, Data: string(body)}, &res)
	_ = json.Unmarshal([]byte(res.Data), &out)
	if out.Error == "" {
		t.Fatalf("non-empty dir without recursive should fail")
	}

	body, _ = json.Marshal(model.FsDeleteRequest{Path: sub, Recursive: true})
	res = pb.TaskResult{}
	handleFsDeleteTask(&pb.Task{Type: model.TaskTypeFsDelete, Data: string(body)}, &res)
	unmarshalResult(t, &res, &out)
	if _, err := os.Stat(sub); !os.IsNotExist(err) {
		t.Fatalf("recursive delete didn't take effect")
	}
}

func TestFsDelete_RefusesRoot(t *testing.T) {
	body, _ := json.Marshal(model.FsDeleteRequest{Path: "/", Recursive: true})
	var res pb.TaskResult
	handleFsDeleteTask(&pb.Task{Type: model.TaskTypeFsDelete, Data: string(body)}, &res)
	var out model.FsDeleteResult
	_ = json.Unmarshal([]byte(res.Data), &out)
	if out.Error == "" {
		t.Fatalf("must refuse /")
	}
}
