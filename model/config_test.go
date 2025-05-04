package model

import (
	"encoding/json"
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
