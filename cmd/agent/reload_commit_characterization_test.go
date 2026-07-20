package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

func TestApplyPendingReloadCharacterizationCommitsPersistedGenerationBeforeRuntimeUse(t *testing.T) {
	// Given
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	t.Cleanup(func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		clearReloadTimer()
		drainReloadSignal()
	})

	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte("server: server-a:5555\nclient_secret: secret-a\nuuid: 00000000-0000-0000-0000-00000000000a\n"), 0o600); err != nil {
		t.Fatalf("seed config A: %v", err)
	}
	if err := agentConfig.Read(configPath); err != nil {
		t.Fatalf("read config A: %v", err)
	}
	publishRuntimeConfig(agentConfig)
	pending := agentConfig.Clone()
	pending.Server = "server-b:5555"
	pending.ClientSecret = "secret-b"
	pending.UUID = "00000000-0000-0000-0000-00000000000b"

	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	// When
	applyPendingReload(active, pending)

	// Then
	var persisted model.AgentConfig
	if err := persisted.Read(configPath); err != nil {
		t.Fatalf("read persisted config B: %v", err)
	}
	if persisted.Server != "server-b:5555" || persisted.ClientSecret != "secret-b" || persisted.UUID != "00000000-0000-0000-0000-00000000000b" {
		t.Fatalf("successful reload must persist complete B before publication: %+v", persisted)
	}
	if agentConfig.Server != persisted.Server || agentConfig.ClientSecret != persisted.ClientSecret || agentConfig.UUID != persisted.UUID {
		t.Fatalf("live config must match persisted B after successful save: live=%+v persisted=%+v", agentConfig, persisted)
	}
	published := loadRuntimeConfig()
	if published.Server != persisted.Server || published.ClientSecret != persisted.ClientSecret || published.UUID != persisted.UUID {
		t.Fatalf("published runtime generation must match persisted B: published=%+v persisted=%+v", published, persisted)
	}
}

func TestApplyPendingReloadCharacterizationKeepsGenerationAfterFailedSave(t *testing.T) {
	// Given
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	t.Cleanup(func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		clearReloadTimer()
	})

	agentConfig = model.AgentConfig{Server: "server-a:5555", ClientSecret: "secret-a", UUID: "uuid-a"}
	sentinel := publishRuntimeConfig(agentConfig)
	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	// When
	applyPendingReload(active, model.AgentConfig{Server: "server-b:5555", ClientSecret: "secret-b", UUID: "uuid-b"})

	// Then
	if agentConfig.Server != "server-a:5555" || agentConfig.ClientSecret != "secret-a" || agentConfig.UUID != "uuid-a" {
		t.Fatalf("failed save must keep complete generation A: %+v", agentConfig)
	}
	if runtimeConfigSnapshot.Load() != sentinel {
		t.Fatal("failed save must keep published generation A")
	}
	reloadMu.Lock()
	stillPending := reloadTimer == active
	reloadMu.Unlock()
	if !stillPending {
		t.Fatal("failed save must keep the active timer available for supersede")
	}
}

func TestCredentialRotationCharacterizationNewConnectionUsesPublishedGeneration(t *testing.T) {
	// Given
	originalSnapshot := runtimeConfigSnapshot.Load()
	t.Cleanup(func() {
		runtimeConfigSnapshot.Store(originalSnapshot)
	})
	publishRuntimeConfig(model.AgentConfig{ClientSecret: "secret-a", UUID: "uuid-a"})
	publishRuntimeConfig(model.AgentConfig{ClientSecret: "secret-b", UUID: "uuid-b"})
	auth := loadConnectionConfigTuple().Auth

	// When
	metadata, err := auth.GetRequestMetadata(context.Background())

	// Then
	if err != nil {
		t.Fatalf("new connection metadata: %v", err)
	}
	if metadata["client-secret"] != "secret-b" || metadata["client-uuid"] != "uuid-b" {
		t.Fatalf("new connection after rotation must use generation B: %v", metadata)
	}
}

func TestPreRunCharacterizationPublishesValidatedStartupConfig(t *testing.T) {
	// Given
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	originalArch := arch
	t.Cleanup(func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		arch = originalArch
	})
	arch = runtime.GOARCH
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte("server: startup.example:5555\nclient_secret: startup-secret\nuuid: 00000000-0000-0000-0000-00000000000a\ntls: true\ninsecure_tls: true\n"), 0o600); err != nil {
		t.Fatalf("seed startup config: %v", err)
	}
	sentinel := publishRuntimeConfig(model.AgentConfig{Server: "sentinel"})

	// When
	err := preRun(configPath)

	// Then
	if err != nil {
		t.Fatalf("preRun: %v", err)
	}
	published := runtimeConfigSnapshot.Load()
	if published == sentinel {
		t.Fatal("successful startup read must publish a runtime generation")
	}
	if published.Server != "startup.example:5555" || published.ClientSecret != "startup-secret" || published.UUID != "00000000-0000-0000-0000-00000000000a" || !published.TLS || !published.InsecureTLS {
		t.Fatalf("startup publication must contain the validated generation: %+v", published)
	}
}
