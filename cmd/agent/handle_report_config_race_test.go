package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func TestHandleReportConfigTaskObservesCompletePublishedGeneration(t *testing.T) {
	// Given
	restoreRuntimeConfigSnapshot(t)
	a := model.AgentConfig{ClientSecret: "secret-a", UUID: "uuid-a"}
	b := model.AgentConfig{ClientSecret: "secret-b", UUID: "uuid-b"}
	publishRuntimeConfig(a)
	const rounds = 500

	// When
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for index := range rounds {
			if index%2 == 0 {
				publishRuntimeConfig(a)
			} else {
				publishRuntimeConfig(b)
			}
		}
	}()
	results := make(chan model.AgentConfig, rounds)
	failures := make(chan error, 1)
	go func() {
		defer wait.Done()
		for iteration := range rounds {
			var result pb.TaskResult
			handleReportConfigTaskWithConfig(loadRuntimeConfig(), &result)
			observed, err := decodeReportConfigResult(iteration, &result)
			if err != nil {
				failures <- err
				return
			}
			results <- observed
		}
	}()
	wait.Wait()
	close(results)
	close(failures)

	// Then
	if err := <-failures; err != nil {
		t.Fatal(err)
	}
	observations := 0
	for observed := range results {
		observations++
		completeA := observed.ClientSecret == a.ClientSecret && observed.UUID == a.UUID
		completeB := observed.ClientSecret == b.ClientSecret && observed.UUID == b.UUID
		if !completeA && !completeB {
			t.Fatalf("torn report config generation: secret=%q uuid=%q", observed.ClientSecret, observed.UUID)
		}
	}
	if observations < 100 {
		t.Fatalf("successful ReportConfig observations=%d, want at least 100", observations)
	}
}

func TestDecodeReportConfigResultRejectsUnsuccessfulResponse(t *testing.T) {
	result := pb.TaskResult{Data: "another reload is in process"}

	if _, err := decodeReportConfigResult(17, &result); err == nil {
		t.Fatal("ReportConfig decoder accepted an unsuccessful response")
	}
}

func decodeReportConfigResult(iteration int, result *pb.TaskResult) (model.AgentConfig, error) {
	if !result.Successful {
		return model.AgentConfig{}, fmt.Errorf("ReportConfig iteration %d failed: %s", iteration, result.Data)
	}
	var observed model.AgentConfig
	if err := json.Unmarshal([]byte(result.Data), &observed); err != nil {
		return model.AgentConfig{}, fmt.Errorf("unmarshal ReportConfig iteration %d: %w", iteration, err)
	}
	return observed, nil
}
