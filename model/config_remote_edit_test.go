package model

import "testing"

func validRemoteEditBase() AgentConfig {
	return AgentConfig{
		Server:       "dashboard.example:5555",
		ClientSecret: "client-secret-value",
		UUID:         "11111111-2222-4333-8444-555555555555",
		ReportDelay:  3,
	}
}

// A remote edit is merged over the running configuration and then persisted.
// If the result has no server address or an unparsable UUID the agent can
// never reconnect, and it cannot be fixed remotely any more either.
func TestValidateConfig_RemoteEditCannotStrandTheAgent(t *testing.T) {
	cases := map[string]func(*AgentConfig){
		"empty server":        func(c *AgentConfig) { c.Server = "" },
		"empty client secret": func(c *AgentConfig) { c.ClientSecret = "" },
		"malformed uuid":      func(c *AgentConfig) { c.UUID = "not-a-uuid" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := validRemoteEditBase()
			mutate(&config)
			if err := ValidateConfig(&config, true); err == nil {
				t.Fatal("remote edit accepted a configuration the agent cannot reconnect with")
			}
		})
	}
}

func TestValidateConfig_RemoteEditAcceptsCompleteConfiguration(t *testing.T) {
	config := validRemoteEditBase()
	config.Server = "new-dashboard.example:443"

	if err := ValidateConfig(&config, true); err != nil {
		t.Fatalf("complete remote edit rejected: %v", err)
	}
}
