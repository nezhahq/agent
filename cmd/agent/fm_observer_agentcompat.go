//go:build agentcompat

package main

import (
	"encoding/json"
	"net"
	"os"
	"time"
)

type fmProducerObservation struct {
	RunID     string `json:"run_id"`
	AgentUUID string `json:"agent_uuid"`
	SessionID string `json:"session_id"`
	Phase     string `json:"phase"`
	Active    int64  `json:"active"`
}

func observeFMProducer(sessionID, phase string, active int64) {
	socketPath := os.Getenv("AGENTCOMPAT_FM_OBSERVER_SOCKET")
	runID := os.Getenv("AGENTCOMPAT_FM_OBSERVER_RUN_ID")
	if socketPath == "" || runID == "" {
		return
	}
	connection, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		printf("FM observer dial failed: %v", err)
		return
	}
	defer connection.Close()
	observation := fmProducerObservation{
		RunID: runID, AgentUUID: loadRuntimeConfig().UUID, SessionID: sessionID,
		Phase: phase, Active: active,
	}
	if err := json.NewEncoder(connection).Encode(observation); err != nil {
		printf("FM observer write failed: %v", err)
	}
}
