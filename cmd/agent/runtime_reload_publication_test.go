package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

func TestApplyPendingReloadPublishesRuntimeConfigAfterSuccessfulSave(t *testing.T) {
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
	pending := model.AgentConfig{}
	if err := pending.Read(configPath); err != nil {
		t.Fatalf("read config A: %v", err)
	}
	pending.Server = "server-b:5555"
	pending.ClientSecret = "secret-b"
	pending.UUID = "00000000-0000-0000-0000-00000000000b"
	sentinel := publishRuntimeConfig(model.AgentConfig{Server: "sentinel"})
	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	// When
	applyPendingReload(active, pending)

	// Then
	published := runtimeConfigSnapshot.Load()
	if published == sentinel {
		t.Fatal("successful current reload must publish a new runtime generation")
	}
	if published.Server != "server-b:5555" || published.ClientSecret != "secret-b" || published.UUID != "00000000-0000-0000-0000-00000000000b" {
		t.Fatalf("successful current reload published incomplete generation B: %+v", published)
	}
}

func TestRuntimeConfigPublishPrecedesWorkerNotification(t *testing.T) {
	// Given
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	t.Cleanup(func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
	})
	publishRuntimeConfig(model.AgentConfig{Server: "server-a:5555"})
	var observed *model.AgentConfig

	// When
	applyCommittedRuntimeConfig(model.AgentConfig{Server: "server-b:5555"}, func() {
		observed = loadRuntimeConfig()
	})

	// Then
	if observed == nil || observed.Server != "server-b:5555" {
		t.Fatalf("worker notification observed before generation B publication: %+v", observed)
	}
}

func TestApplyPendingReloadFailedStaleAndSupersededDoNotPublishRuntimeConfig(t *testing.T) {
	t.Run("failed save", func(t *testing.T) {
		originalSnapshot := runtimeConfigSnapshot.Load()
		t.Cleanup(func() {
			runtimeConfigSnapshot.Store(originalSnapshot)
			clearReloadTimer()
		})
		sentinel := publishRuntimeConfig(model.AgentConfig{Server: "server-a:5555"})
		active := time.AfterFunc(time.Hour, func() {})
		defer active.Stop()
		reloadMu.Lock()
		reloadTimer = active
		reloadMu.Unlock()

		applyPendingReload(active, model.AgentConfig{Server: "server-b:5555"})

		if runtimeConfigSnapshot.Load() != sentinel {
			t.Fatal("failed save must not publish a runtime generation")
		}
	})

	t.Run("stale or superseded timer", func(t *testing.T) {
		originalSnapshot := runtimeConfigSnapshot.Load()
		t.Cleanup(func() {
			runtimeConfigSnapshot.Store(originalSnapshot)
			clearReloadTimer()
		})
		sentinel := publishRuntimeConfig(model.AgentConfig{Server: "server-a:5555"})
		stale := time.AfterFunc(time.Hour, func() {})
		defer stale.Stop()
		active := time.AfterFunc(time.Hour, func() {})
		defer active.Stop()
		reloadMu.Lock()
		reloadTimer = active
		reloadMu.Unlock()

		applyPendingReload(stale, model.AgentConfig{Server: "server-b:5555"})

		if runtimeConfigSnapshot.Load() != sentinel {
			t.Fatal("stale or superseded timer must not publish a runtime generation")
		}
	})
}

func TestApplyPendingReloadCoalescesReconnectSignalWhenWorkerIsNotReceiving(t *testing.T) {
	// Given
	originalConfig := agentConfig
	t.Cleanup(func() {
		agentConfig = originalConfig
		clearReloadTimer()
		drainReloadSignal()
	})
	drainReloadSignal()
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte("server: server-a:5555\nclient_secret: secret-a\nuuid: 00000000-0000-0000-0000-00000000000a\n"), 0o600); err != nil {
		t.Fatalf("seed config A: %v", err)
	}
	pending := model.AgentConfig{}
	if err := pending.Read(configPath); err != nil {
		t.Fatalf("read config A: %v", err)
	}
	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	// When
	applyPendingReload(active, pending)

	// Then
	select {
	case <-reloadSigChan:
	default:
		t.Fatal("successful reload must leave one eventual reconnect signal when no worker is receiving")
	}
}

func TestReloadSignalCoalescesWhenBufferAlreadyContainsSignal(t *testing.T) {
	// Given
	drainReloadSignal()
	t.Cleanup(drainReloadSignal)
	if cap(reloadSigChan) != 1 {
		t.Fatalf("reload signal must have capacity 1 for coalescing, got %d", cap(reloadSigChan))
	}
	reloadSigChan <- struct{}{}

	// When
	notifyReloadWorker()

	// Then
	select {
	case <-reloadSigChan:
	default:
		t.Fatal("a full reload signal buffer must retain the eventual reconnect notification")
	}
	select {
	case <-reloadSigChan:
		t.Fatal("coalescing must retain at most one pending reconnect notification")
	default:
	}
}

func drainReloadSignal() {
	select {
	case <-reloadSigChan:
	default:
	}
}
