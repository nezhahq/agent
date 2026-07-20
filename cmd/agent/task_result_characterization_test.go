package main

import (
	"bytes"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/protobuf/proto"
)

func TestTaskResultWireBytesRemainStable(t *testing.T) {
	// Given
	result := &pb.TaskResult{
		Id:         150,
		Type:       model.TaskTypeFsTransfer,
		Data:       "ok",
		Successful: true,
	}
	want := []byte{0x08, 0x96, 0x01, 0x10, 0x14, 0x22, 0x02, 'o', 'k', 0x28, 0x01}

	// When
	got, err := proto.Marshal(result)

	// Then
	if err != nil {
		t.Fatalf("marshal TaskResult: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("TaskResult wire bytes = %x, want %x", got, want)
	}
}

func TestDispatchAgentTaskRunsPlainApplyConfigSynchronously(t *testing.T) {
	// Given
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()
	setTestRuntimeConfig(model.AgentConfig{
		ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		TLS:          true,
	})
	task := &pb.Task{Id: 91, Type: model.TaskTypeApplyConfig, Data: `{"debug":true}`}
	sent := make(chan *pb.TaskResult, 1)

	// When
	dispatchAgentTask(task, func(result *pb.TaskResult) error {
		sent <- result
		return nil
	}, func() {})

	// Then
	if !reloadPending() {
		t.Fatal("plain ApplyConfig must schedule reload before dispatch returns")
	}
	select {
	case result := <-sent:
		if result.GetId() != task.GetId() || result.GetType() != task.GetType() || !result.GetSuccessful() {
			t.Fatalf("synchronous ApplyConfig result = %+v, want id=%d type=%d successful", result, task.GetId(), task.GetType())
		}
	default:
		t.Fatal("plain ApplyConfig must send result before dispatch returns")
	}
}
