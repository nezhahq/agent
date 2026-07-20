package main

import (
	"testing"

	"github.com/nezhahq/agent/model"
)

func restoreRuntimeConfigSnapshot(t *testing.T) {
	t.Helper()
	original := runtimeConfigSnapshot.Load()
	t.Cleanup(func() {
		runtimeConfigSnapshot.Store(original)
	})
}

func TestRuntimeConfigPublishDeepCopiesReferenceFields(t *testing.T) {
	restoreRuntimeConfigSnapshot(t)
	source := model.AgentConfig{
		ClientSecret:                "secret",
		UUID:                        "uuid",
		HardDrivePartitionAllowlist: []string{"/data"},
		NICAllowlist:                map[string]bool{"eth0": true},
		DNS:                         []string{"1.1.1.1:53"},
		CustomIPApi:                 []string{"https://ip.example.test"},
	}

	first := publishRuntimeConfig(source)
	source.HardDrivePartitionAllowlist[0] = "/mutated"
	source.NICAllowlist["eth0"] = false
	source.DNS[0] = "9.9.9.9:53"
	source.CustomIPApi[0] = "https://mutated.example.test"

	loaded := loadRuntimeConfig()
	if loaded != first {
		t.Fatal("loadRuntimeConfig must return the currently published generation pointer")
	}
	if loaded.HardDrivePartitionAllowlist[0] != "/data" || !loaded.NICAllowlist["eth0"] || loaded.DNS[0] != "1.1.1.1:53" || loaded.CustomIPApi[0] != "https://ip.example.test" {
		t.Fatalf("published runtime config retained a source alias: %+v", loaded)
	}

	second := publishRuntimeConfig(model.AgentConfig{ClientSecret: "next"})
	if second == first {
		t.Fatal("each publication must install a distinct immutable generation")
	}
}

func TestRuntimeConfigPublishPreservesNilReferenceFields(t *testing.T) {
	restoreRuntimeConfigSnapshot(t)
	published := publishRuntimeConfig(model.AgentConfig{})

	if published.HardDrivePartitionAllowlist != nil || published.NICAllowlist != nil || published.DNS != nil || published.CustomIPApi != nil {
		t.Fatalf("publication must preserve nil reference fields: %+v", published)
	}
}
