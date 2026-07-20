package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
)

func TestApplyPendingReloadKeepsLiveConfigWhenSaveFails(t *testing.T) {
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	defer func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		clearReloadTimer()
	}()

	directory := t.TempDir()
	livePath := filepath.Join(directory, "live-config.yml")
	configPath := filepath.Join(directory, "config.yml")
	originalBytes := []byte("server: server-a:5555\nclient_secret: live\nuuid: 00000000-0000-0000-0000-00000000000a\n")
	if err := os.WriteFile(livePath, originalBytes, 0o600); err != nil {
		t.Fatalf("seed live config: %v", err)
	}
	if err := os.Symlink(livePath, configPath); err != nil {
		t.Fatalf("link live config: %v", err)
	}
	if err := agentConfig.Read(configPath); err != nil {
		t.Fatalf("read live config: %v", err)
	}
	sentinel := publishRuntimeConfig(agentConfig)
	pending := agentConfig.Clone()
	pending.Server = "server-b:5555"
	pending.ClientSecret = "unsaved"
	pending.UUID = "00000000-0000-0000-0000-00000000000b"
	blockedTarget := filepath.Join(directory, "blocked-target")
	if err := os.Mkdir(blockedTarget, 0o700); err != nil {
		t.Fatalf("create blocked target: %v", err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatalf("remove live config link: %v", err)
	}
	if err := os.Symlink(blockedTarget, configPath); err != nil {
		t.Fatalf("link blocked target: %v", err)
	}

	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	applyPendingReload(active, pending)

	if agentConfig.ClientSecret != "live" {
		t.Fatalf("failed Save must leave the live config unchanged, got %q", agentConfig.ClientSecret)
	}
	if runtimeConfigSnapshot.Load() != sentinel {
		t.Fatal("failed Save must leave the published runtime generation unchanged")
	}
	reloadMu.Lock()
	stillPending := reloadTimer == active
	reloadMu.Unlock()
	if !stillPending {
		t.Fatal("failed Save must leave the active reload pending for a later supersede")
	}
	persisted, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatalf("read live config after failed Save: %v", err)
	}
	if string(persisted) != string(originalBytes) {
		t.Fatalf("failed Save changed on-disk config: got %q want %q", persisted, originalBytes)
	}
}

func TestScheduleConfigReloadSupersedesEarlierDelayedTimer(t *testing.T) {
	defer clearReloadTimer()

	reloadMu.Lock()
	scheduleConfigReload(model.AgentConfig{ClientSecret: "first"}, false)
	first := reloadTimer
	scheduleConfigReload(model.AgentConfig{ClientSecret: "second"}, true)
	second := reloadTimer
	isTransfer := reloadIsTransfer
	reloadMu.Unlock()

	if first == nil || second == nil {
		t.Fatal("each delayed reload must install a timer")
	}
	if first == second {
		t.Fatal("a newer delayed reload must replace the earlier timer")
	}
	if !isTransfer {
		t.Fatal("the newer delayed reload must replace the pending transfer metadata")
	}
}

// Race scenario: T1's AfterFunc callback gets queued to run after its 10s
// (or shorter) delay, but is preempted before it acquires reloadMu. T2 then
// arrives, acquires reloadMu, calls T1.Stop() (returns false: too late),
// installs its own timer as reloadTimer, releases the mutex. T1's stale
// callback resumes, acquires the mutex, and — if it only checks
// `reloadTimer == nil` — observes "non-nil" (it's T2's timer), happily
// commits T1's superseded config to disk and to agentConfig, and sets
// reloadTimer back to nil. T2's callback then fires, sees nil, exits — the
// agent silently locked itself out with the cancelled credential.
//
// The identity check (`reloadTimer != thisTimer`) closes the window. This
// test reproduces the race against the helper that performs the commit.
func TestApplyPendingReloadSkipsWhenSuperseded(t *testing.T) {
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	defer func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		clearReloadTimer()
	}()

	configPath := filepath.Join(t.TempDir(), "config.yml")
	originalBytes := []byte("server: server-a:5555\nclient_secret: live\nuuid: 00000000-0000-0000-0000-00000000000a\n")
	if err := os.WriteFile(configPath, originalBytes, 0o600); err != nil {
		t.Fatalf("seed live config: %v", err)
	}
	if err := agentConfig.Read(configPath); err != nil {
		t.Fatalf("read live config: %v", err)
	}
	sentinel := publishRuntimeConfig(agentConfig)
	pending := agentConfig.Clone()
	pending.Server = "server-b:5555"
	pending.ClientSecret = "superseded"
	pending.UUID = "00000000-0000-0000-0000-00000000000b"

	// stale stands in for a timer whose AfterFunc body already started but
	// hadn't yet acquired reloadMu when supersede ran.
	stale := time.AfterFunc(time.Hour, func() {})
	defer stale.Stop()

	// active is the newer timer that supersede installed under the lock.
	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()

	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	applyPendingReload(stale, pending)

	if agentConfig.ClientSecret != "live" {
		t.Fatalf("stale-timer callback must not clobber live agentConfig, got %q", agentConfig.ClientSecret)
	}
	reloadMu.Lock()
	stillActive := reloadTimer == active
	reloadMu.Unlock()
	if !stillActive {
		t.Fatal("the active reload timer must remain installed after a stale callback returns")
	}
	if runtimeConfigSnapshot.Load() != sentinel {
		t.Fatal("stale-timer callback must leave the published runtime generation unchanged")
	}
	persisted, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config after stale callback: %v", err)
	}
	if string(persisted) != string(originalBytes) {
		t.Fatalf("stale-timer callback changed on-disk config: got %q want %q", persisted, originalBytes)
	}
}

func TestApplyPendingReloadDeepCopiesReferenceFields(t *testing.T) {
	originalConfig := agentConfig
	originalSnapshot := runtimeConfigSnapshot.Load()
	defer func() {
		agentConfig = originalConfig
		runtimeConfigSnapshot.Store(originalSnapshot)
		clearReloadTimer()
	}()

	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte("server: example.com:5555\nclient_secret: original\nuuid: 00000000-0000-0000-0000-000000000001\n"), 0600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	pending := model.AgentConfig{}
	if err := pending.Read(configPath); err != nil {
		t.Fatalf("read config: %v", err)
	}
	pending.HardDrivePartitionAllowlist = []string{"/data"}
	pending.NICAllowlist = map[string]bool{"eth0": true}
	pending.DNS = []string{"1.1.1.1:53"}
	pending.CustomIPApi = []string{"https://ip.example.test"}

	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	applyPendingReload(active, pending)
	publishedBeforeMutation := runtimeConfigSnapshot.Load()
	persistedBeforeMutation, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read persisted config before source mutation: %v", err)
	}

	pending.HardDrivePartitionAllowlist[0] = "/mutated"
	pending.NICAllowlist["eth0"] = false
	pending.DNS[0] = "9.9.9.9:53"
	pending.CustomIPApi[0] = "https://mutated.example.test"

	published := loadRuntimeConfig()
	if runtimeConfigSnapshot.Load() != publishedBeforeMutation {
		t.Fatal("source mutation replaced the published runtime snapshot pointer")
	}
	if published.HardDrivePartitionAllowlist[0] != "/data" || !published.NICAllowlist["eth0"] || published.DNS[0] != "1.1.1.1:53" || published.CustomIPApi[0] != "https://ip.example.test" {
		t.Fatalf("published runtime generation retained a caller alias: %+v", published)
	}
	if got := agentConfig.HardDrivePartitionAllowlist[0]; got != "/data" {
		t.Fatalf("published disk allowlist retained a caller alias: got %q", got)
	}
	if got := agentConfig.NICAllowlist["eth0"]; !got {
		t.Fatal("published NIC allowlist retained a caller alias")
	}
	if got := agentConfig.DNS[0]; got != "1.1.1.1:53" {
		t.Fatalf("published DNS retained a caller alias: got %q", got)
	}
	if got := agentConfig.CustomIPApi[0]; got != "https://ip.example.test" {
		t.Fatalf("published custom IP API retained a caller alias: got %q", got)
	}
	persistedAfterMutation, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read persisted config after source mutation: %v", err)
	}
	if string(persistedAfterMutation) != string(persistedBeforeMutation) {
		t.Fatal("source mutation changed the persisted configuration")
	}
}
