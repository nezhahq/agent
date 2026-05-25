package model

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestJsonUnmarshalConfig(t *testing.T) {
	var conf AgentConfig
	conf.Debug = true
	t.Logf("old conf: %+v", conf)
	var newConfJson = "{\"gpu\": true}"
	if err := json.Unmarshal([]byte(newConfJson), &conf); err != nil {
		t.Errorf("json unmarshal failed: %v", err)
	}
	t.Logf("new conf: %+v", conf)
	if conf.GPU != true {
		t.Errorf("json unmarshal failed: %v", conf.GPU)
	}
	if conf.Debug != true {
		t.Errorf("json unmarshal failed: %v", conf.Debug)
	}
}

// HIGH security regression: Save() must produce a file with mode 0600
// regardless of any pre-existing mode. os.WriteFile only applies the perm
// argument on CREATE; if config.yml already exists with 0644 (older
// install, hand-edit, distro packaging) the rotated HandshakeSecret would
// be written to a world-readable file. Same-host low-privilege users could
// then read the credential and impersonate the agent.
func TestAgentConfigSaveTightensFilePermissionsTo0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode semantics are unix-specific")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	if err := os.WriteFile(path, []byte("server: \"old:5555\"\nclient_secret: \"original\"\nuuid: \"00000000-0000-0000-0000-000000000001\"\n"), 0644); err != nil {
		t.Fatalf("seed pre-existing 0644 config: %v", err)
	}

	cfg := AgentConfig{}
	if err := cfg.Read(path); err != nil {
		t.Fatalf("Read: %v", err)
	}

	cfg.ClientSecret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := cfg.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Fatalf("Save must enforce mode 0600 even when the pre-existing file was 0644; got %#o", mode)
	}
}
