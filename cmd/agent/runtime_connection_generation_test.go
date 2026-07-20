package main

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/nezhahq/agent/model"
)

func TestAuthHandlerSnapshotRemainsGenerationAAfterPublishingB(t *testing.T) {
	// Given
	restoreConnectionGenerationGlobals(t)
	agentConfig = model.AgentConfig{
		Server:       "server-a:5555",
		ClientSecret: "secret-a",
		UUID:         "uuid-a",
		TLS:          false,
	}
	publishRuntimeConfig(agentConfig)
	authA := loadConnectionConfigTuple().Auth

	// When
	generationB := model.AgentConfig{
		Server:       "server-b:5555",
		ClientSecret: "secret-b",
		UUID:         "uuid-b",
		TLS:          true,
	}
	publishRuntimeConfig(generationB)
	agentConfig = generationB
	metadata, err := authA.GetRequestMetadata(context.Background())

	// Then
	if err != nil {
		t.Fatalf("generation A metadata: %v", err)
	}
	if metadata["client-secret"] != "secret-a" || metadata["client-uuid"] != "uuid-a" {
		t.Fatalf("generation A handler changed after B publication: %v", metadata)
	}
	if authA.RequireTransportSecurity() {
		t.Fatal("generation A handler changed its TLS policy after B publication")
	}
}

func TestConnectionConfigTupleLoadsCompleteGenerationB(t *testing.T) {
	// Given
	restoreConnectionGenerationGlobals(t)
	agentConfig = model.AgentConfig{
		Server:       "server-a:5555",
		ClientSecret: "secret-a",
		UUID:         "uuid-a",
		TLS:          false,
		InsecureTLS:  false,
	}
	publishRuntimeConfig(model.AgentConfig{
		Server:       "server-b:5555",
		ClientSecret: "secret-b",
		UUID:         "uuid-b",
		TLS:          true,
		InsecureTLS:  true,
	})

	// When
	tuple := loadConnectionConfigTuple()
	metadata, err := tuple.Auth.GetRequestMetadata(context.Background())

	// Then
	if err != nil {
		t.Fatalf("generation B metadata: %v", err)
	}
	if tuple.Server != "server-b:5555" || !tuple.TLS || !tuple.InsecureTLS {
		t.Fatalf("connection tuple must load complete generation B: %+v", tuple)
	}
	if metadata["client-secret"] != "secret-b" || metadata["client-uuid"] != "uuid-b" || !tuple.Auth.RequireTransportSecurity() {
		t.Fatalf("connection auth must match generation B: metadata=%v requireTLS=%v", metadata, tuple.Auth.RequireTransportSecurity())
	}
}

func TestPlaintextGenerationAConnectionNeverReceivesGenerationBSecret(t *testing.T) {
	// Given
	restoreConnectionGenerationGlobals(t)
	generationA := model.AgentConfig{ClientSecret: "secret-a", UUID: "uuid-a", TLS: false}
	agentConfig = generationA
	publishRuntimeConfig(generationA)
	plaintextAuthA := loadConnectionConfigTuple().Auth

	// When
	generationB := model.AgentConfig{ClientSecret: "secret-b", UUID: "uuid-b", TLS: true}
	agentConfig = generationB
	publishRuntimeConfig(generationB)
	metadata, err := plaintextAuthA.GetRequestMetadata(context.Background())

	// Then
	if err != nil {
		t.Fatalf("plaintext generation A metadata: %v", err)
	}
	if plaintextAuthA.RequireTransportSecurity() {
		t.Fatal("plaintext generation A connection must retain its original transport policy")
	}
	if metadata["client-secret"] != "secret-a" {
		t.Fatalf("plaintext generation A connection received another generation's secret: %v", metadata)
	}
}

func TestRuntimeConfigPublishConcurrentWithReconnectObservesCompleteGenerations(t *testing.T) {
	// Given
	restoreConnectionGenerationGlobals(t)
	generationA := model.AgentConfig{Server: "server-a:5555", ClientSecret: "secret-a", UUID: "uuid-a", TLS: false, InsecureTLS: false}
	generationB := model.AgentConfig{Server: "server-b:5555", ClientSecret: "secret-b", UUID: "uuid-b", TLS: true, InsecureTLS: true}
	publishRuntimeConfig(generationA)
	const writers = 2
	const readers = 8
	const rounds = 1000
	start := make(chan struct{})
	failures := make(chan string, readers)
	var waitGroup sync.WaitGroup
	waitGroup.Add(writers + readers)

	// When
	for writer := 0; writer < writers; writer++ {
		go func(writerID int) {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < rounds; iteration++ {
				if (writerID+iteration)%2 == 0 {
					publishRuntimeConfig(generationB)
				} else {
					publishRuntimeConfig(generationA)
				}
			}
		}(writer)
	}
	for reader := 0; reader < readers; reader++ {
		go func(readerID int) {
			defer waitGroup.Done()
			<-start
			for iteration := 0; iteration < rounds; iteration++ {
				tuple := loadConnectionConfigTuple()
				metadata, err := tuple.Auth.GetRequestMetadata(context.Background())
				if err != nil {
					failures <- fmt.Sprintf("reader %d iteration %d metadata: %v", readerID, iteration, err)
					return
				}
				isA := tuple.Server == generationA.Server && !tuple.TLS && !tuple.InsecureTLS && metadata["client-secret"] == generationA.ClientSecret && metadata["client-uuid"] == generationA.UUID && !tuple.Auth.RequireTransportSecurity()
				isB := tuple.Server == generationB.Server && tuple.TLS && tuple.InsecureTLS && metadata["client-secret"] == generationB.ClientSecret && metadata["client-uuid"] == generationB.UUID && tuple.Auth.RequireTransportSecurity()
				if !isA && !isB {
					failures <- fmt.Sprintf("reader %d iteration %d observed mixed generation: tuple=%+v metadata=%v", readerID, iteration, tuple, metadata)
					return
				}
			}
		}(reader)
	}
	close(start)
	waitGroup.Wait()
	close(failures)

	// Then
	for failure := range failures {
		t.Fatal(failure)
	}
}

func TestRuntimeConfigGenerationManualQAOldConnectionStaysAAndNewConnectionUsesB(t *testing.T) {
	// Given
	restoreConnectionGenerationGlobals(t)
	generationA := model.AgentConfig{Server: "server-a:5555", ClientSecret: "secret-a", UUID: "uuid-a", TLS: false, InsecureTLS: false}
	generationB := model.AgentConfig{Server: "server-b:5555", ClientSecret: "secret-b", UUID: "uuid-b", TLS: true, InsecureTLS: true}
	publishRuntimeConfig(generationA)
	tupleA := loadConnectionConfigTuple()

	// When
	publishRuntimeConfig(generationB)
	metadataA, err := tupleA.Auth.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("generation A metadata: %v", err)
	}
	tupleB := loadConnectionConfigTuple()
	metadataB, err := tupleB.Auth.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("generation B metadata: %v", err)
	}

	// Then
	if tupleA.Server != generationA.Server || tupleA.TLS || tupleA.InsecureTLS || tupleA.Auth.RequireTransportSecurity() || metadataA["client-secret"] != generationA.ClientSecret || metadataA["client-uuid"] != generationA.UUID {
		t.Fatalf("old connection did not remain complete A: tuple=%+v metadata=%v", tupleA, metadataA)
	}
	if tupleB.Server != generationB.Server || !tupleB.TLS || !tupleB.InsecureTLS || !tupleB.Auth.RequireTransportSecurity() || metadataB["client-secret"] != generationB.ClientSecret || metadataB["client-uuid"] != generationB.UUID {
		t.Fatalf("new connection did not use complete B: tuple=%+v metadata=%v", tupleB, metadataB)
	}
	t.Logf("old connection A: server=%s tls=%v insecureTLS=%v authGeneration=A requireTLS=%v", tupleA.Server, tupleA.TLS, tupleA.InsecureTLS, tupleA.Auth.RequireTransportSecurity())
	t.Logf("new connection B: server=%s tls=%v insecureTLS=%v authGeneration=B requireTLS=%v", tupleB.Server, tupleB.TLS, tupleB.InsecureTLS, tupleB.Auth.RequireTransportSecurity())
}

func restoreConnectionGenerationGlobals(t *testing.T) {
	t.Helper()
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	t.Cleanup(func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
	})
}
