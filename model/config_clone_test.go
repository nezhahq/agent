package model

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAgentConfigValueCopyPreservesPersistenceState(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte("server: example.com:5555\nclient_secret: original\nuuid: 00000000-0000-0000-0000-000000000001\n"), 0600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	source := AgentConfig{}
	if err := source.Read(configPath); err != nil {
		t.Fatalf("read config: %v", err)
	}

	copied := source
	copied.ClientSecret = "rotated"
	if copied.k != source.k {
		t.Fatal("ordinary value copy must preserve the koanf persistence state")
	}
	if copied.filePath != configPath {
		t.Fatalf("ordinary value copy lost filePath: got %q", copied.filePath)
	}
	if err := copied.Save(); err != nil {
		t.Fatalf("save copied config: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("copied config must still save through the original persistence state")
	}
}

func TestAgentConfigCloneDeepCopiesReferenceFieldsAndPreservesPersistenceState(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(configPath, []byte("server: example.com:5555\nclient_secret: original\nuuid: 00000000-0000-0000-0000-000000000001\n"), 0600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	source := AgentConfig{}
	if err := source.Read(configPath); err != nil {
		t.Fatalf("read config: %v", err)
	}
	source.Debug = true
	source.HardDrivePartitionAllowlist = []string{"/data"}
	source.NICAllowlist = map[string]bool{"eth0": true}
	source.DNS = []string{"1.1.1.1:53"}
	source.CustomIPApi = []string{"https://ip.example.test"}

	cloned := source.Clone()
	if !reflect.DeepEqual(cloned, source) {
		t.Fatalf("Clone must preserve every field before either value is mutated: got %+v want %+v", cloned, source)
	}

	source.HardDrivePartitionAllowlist[0] = "/mutated"
	source.NICAllowlist["eth0"] = false
	source.DNS[0] = "9.9.9.9:53"
	source.CustomIPApi[0] = "https://mutated.example.test"

	if !cloned.Debug || cloned.ClientSecret != "original" || cloned.UUID != "00000000-0000-0000-0000-000000000001" {
		t.Fatalf("Clone lost scalar fields: %+v", cloned)
	}
	if cloned.k != source.k || cloned.filePath != configPath {
		t.Fatal("Clone must preserve unexported persistence state")
	}
	if cloned.HardDrivePartitionAllowlist[0] != "/data" || !cloned.NICAllowlist["eth0"] || cloned.DNS[0] != "1.1.1.1:53" || cloned.CustomIPApi[0] != "https://ip.example.test" {
		t.Fatalf("Clone retained a source reference alias: %+v", cloned)
	}
	t.Logf("source mutated while clone stayed independent: source=%+v clone=%+v persistence_path=%s", source, cloned, cloned.filePath)

	nilSource := AgentConfig{}
	nilClone := nilSource.Clone()
	if nilClone.HardDrivePartitionAllowlist != nil || nilClone.NICAllowlist != nil || nilClone.DNS != nil || nilClone.CustomIPApi != nil {
		t.Fatalf("Clone must preserve nil reference fields: %+v", nilClone)
	}
}
