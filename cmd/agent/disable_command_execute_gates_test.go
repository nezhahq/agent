package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/fm"
	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
)

// disable_command_execute is the operator's switch for "this dashboard may
// not touch the host". Each entry point checks it on its own, so each one
// needs a test that fails when its check is removed.

var commandExecutionDisabled = taskFeatureGates{disableCommandExecute: true}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestDisabledCommandExecute_FsWriteCreatesNothing(t *testing.T) {
	target := filepath.Join(t.TempDir(), "written.txt")
	var result pb.TaskResult

	handleFsWriteTaskWithConfig(commandExecutionDisabled, &pb.Task{
		Data: mustJSON(t, model.FsWriteRequest{Path: target, Content: "data", Encoding: "utf8"}),
	}, &result)

	var out model.FsWriteResult
	if err := json.Unmarshal([]byte(result.GetData()), &out); err != nil {
		t.Fatalf("result is not JSON: %v (%s)", err, result.GetData())
	}
	if out.Error == "" {
		t.Fatal("fs.write reported no error although file operations are disabled")
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fs.write created the file although it is disabled (stat err = %v)", err)
	}
}

func TestDisabledCommandExecute_FsDeleteRemovesNothing(t *testing.T) {
	target := filepath.Join(t.TempDir(), "kept.txt")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	var result pb.TaskResult

	handleFsDeleteTaskWithConfig(commandExecutionDisabled, &pb.Task{
		Data: mustJSON(t, model.FsDeleteRequest{Path: target}),
	}, &result)

	var out model.FsDeleteResult
	if err := json.Unmarshal([]byte(result.GetData()), &out); err != nil {
		t.Fatalf("result is not JSON: %v (%s)", err, result.GetData())
	}
	if out.Error == "" || out.DeletedCount != 0 {
		t.Fatalf("fs.delete result = %+v, want a refusal", out)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("fs.delete removed the file although it is disabled: %v", err)
	}
}

func TestDisabledCommandExecute_FsReadAndListDiscloseNothing(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret-name.txt")
	if err := os.WriteFile(secret, []byte("top-secret-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	var readResult pb.TaskResult
	handleFsReadTaskWithConfig(commandExecutionDisabled, &pb.Task{
		Data: mustJSON(t, model.FsReadRequest{Path: secret}),
	}, &readResult)
	var read model.FsReadResult
	if err := json.Unmarshal([]byte(readResult.GetData()), &read); err != nil {
		t.Fatalf("fs.read result is not JSON: %v (%s)", err, readResult.GetData())
	}
	if read.Error == "" || read.Content != "" || strings.Contains(readResult.GetData(), "top-secret-content") {
		t.Fatalf("fs.read disclosed content although it is disabled: %s", readResult.GetData())
	}

	var listResult pb.TaskResult
	handleFsListTaskWithConfig(commandExecutionDisabled, &pb.Task{
		Data: mustJSON(t, model.FsListRequest{Path: dir}),
	}, &listResult)
	var list model.FsListResult
	if err := json.Unmarshal([]byte(listResult.GetData()), &list); err != nil {
		t.Fatalf("fs.list result is not JSON: %v (%s)", err, listResult.GetData())
	}
	if list.Error == "" || len(list.Entries) != 0 || strings.Contains(listResult.GetData(), "secret-name") {
		t.Fatalf("fs.list disclosed entries although it is disabled: %s", listResult.GetData())
	}
}

func TestDisabledCommandExecute_TerminalOpensNoStreamAndNoShell(t *testing.T) {
	handler := newTerminalHandler()
	handler.openStream = func(context.Context) (pb.NezhaService_IOStreamClient, error) {
		t.Error("terminal opened an IOStream although command execution is disabled")
		return nil, errors.New("must not be called")
	}
	handler.startPTY = func() (pty.IPty, error) {
		t.Error("terminal started a shell although command execution is disabled")
		return nil, errors.New("must not be called")
	}

	handler.run(context.Background(), commandExecutionDisabled, &pb.Task{
		Data: mustJSON(t, model.TerminalTask{StreamID: "stream-1"}),
	})
}

func TestDisabledCommandExecute_FileManagerOpensNoStream(t *testing.T) {
	handler := newFMHandler()
	handler.openStream = func(context.Context) (pb.NezhaService_IOStreamClient, error) {
		t.Error("file manager opened an IOStream although command execution is disabled")
		return nil, errors.New("must not be called")
	}
	handler.newTask = func(fm.Dependencies) *fm.Task {
		t.Error("file manager created a task although command execution is disabled")
		return nil
	}

	handler.run(context.Background(), commandExecutionDisabled, &pb.Task{
		Data: mustJSON(t, model.TaskFM{StreamID: "stream-1"}),
	})
}
