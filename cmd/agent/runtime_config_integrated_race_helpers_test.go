package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

type integratedConfigGeneration string

const (
	integratedGenerationA integratedConfigGeneration = "A"
	integratedGenerationB integratedConfigGeneration = "B"
)

type integratedRaceLane struct {
	name    string
	trigger chan struct{}
	observe func() (integratedConfigGeneration, error)
}

type integratedRaceSummary struct {
	name       string
	total      int
	generation map[integratedConfigGeneration]int
}

type integratedRaceCoordinator struct {
	ctx          context.Context
	start        <-chan struct{}
	acknowledged chan struct{}
	summaries    chan integratedRaceSummary
	failures     chan error
	wait         *sync.WaitGroup
}

func integratedGenerationConfig(generation integratedConfigGeneration) model.AgentConfig {
	isB := generation == integratedGenerationB
	marker := "a"
	reportDelay := uint32(1)
	ipReportPeriod := uint32(31)
	if isB {
		marker = "b"
		reportDelay = 4
		ipReportPeriod = 47
	}
	return model.AgentConfig{
		Server:                      "server-" + marker + ":5555",
		ClientSecret:                "secret-" + marker,
		UUID:                        "00000000-0000-0000-0000-00000000000" + marker,
		TLS:                         isB,
		InsecureTLS:                 isB,
		DNS:                         []string{"dns-" + marker + ":53"},
		ReportDelay:                 reportDelay,
		IPReportPeriod:              ipReportPeriod,
		SkipConnectionCount:         !isB,
		SkipProcsCount:              !isB,
		UseIPv6CountryCode:          isB,
		DisableForceUpdate:          isB,
		DisableCommandExecute:       isB,
		DisableNat:                  isB,
		DisableSendQuery:            isB,
		GPU:                         !isB,
		Temperature:                 !isB,
		HardDrivePartitionAllowlist: []string{"/disk-" + marker},
		NICAllowlist:                map[string]bool{"nic-" + marker: true},
		CustomIPApi:                 []string{"https://ip-" + marker + ".example.test"},
	}
}

func mutateIntegratedGenerationSource(config *model.AgentConfig) {
	config.DNS[0] = "mutated-dns:53"
	config.HardDrivePartitionAllowlist[0] = "/mutated-disk"
	for name := range config.NICAllowlist {
		config.NICAllowlist[name] = false
	}
	config.CustomIPApi[0] = "https://mutated.example.test"
}

func classifyIntegratedConfig(config *model.AgentConfig) (integratedConfigGeneration, error) {
	a := integratedGenerationConfig(integratedGenerationA)
	b := integratedGenerationConfig(integratedGenerationB)
	if integratedConfigMatches(config, a) {
		return integratedGenerationA, nil
	}
	if integratedConfigMatches(config, b) {
		return integratedGenerationB, nil
	}
	return "", fmt.Errorf("torn config: server=%q secret=%q uuid=%q tls=%t insecure=%t dns=%v report={delay:%d ip:%d skipConn:%t skipProcs:%t use6:%t} task={force:%t nat:%t query:%t} monitor={gpu:%t temperature:%t disks:%v nics:%v endpoints:%v}", config.Server, config.ClientSecret, config.UUID, config.TLS, config.InsecureTLS, config.DNS, config.ReportDelay, config.IPReportPeriod, config.SkipConnectionCount, config.SkipProcsCount, config.UseIPv6CountryCode, config.DisableForceUpdate, config.DisableNat, config.DisableSendQuery, config.GPU, config.Temperature, config.HardDrivePartitionAllowlist, config.NICAllowlist, config.CustomIPApi)
}

func integratedConfigMatches(observed *model.AgentConfig, expected model.AgentConfig) bool {
	return observed.Server == expected.Server &&
		observed.ClientSecret == expected.ClientSecret &&
		observed.UUID == expected.UUID &&
		observed.TLS == expected.TLS &&
		observed.InsecureTLS == expected.InsecureTLS &&
		slices.Equal(observed.DNS, expected.DNS) &&
		observed.ReportDelay == expected.ReportDelay &&
		observed.IPReportPeriod == expected.IPReportPeriod &&
		observed.SkipConnectionCount == expected.SkipConnectionCount &&
		observed.SkipProcsCount == expected.SkipProcsCount &&
		observed.UseIPv6CountryCode == expected.UseIPv6CountryCode &&
		observed.DisableForceUpdate == expected.DisableForceUpdate &&
		observed.DisableCommandExecute == expected.DisableCommandExecute &&
		observed.DisableNat == expected.DisableNat &&
		observed.DisableSendQuery == expected.DisableSendQuery &&
		observed.GPU == expected.GPU &&
		observed.Temperature == expected.Temperature &&
		slices.Equal(observed.HardDrivePartitionAllowlist, expected.HardDrivePartitionAllowlist) &&
		maps.Equal(observed.NICAllowlist, expected.NICAllowlist) &&
		slices.Equal(observed.CustomIPApi, expected.CustomIPApi)
}

func observeIntegratedConnection() (integratedConfigGeneration, error) {
	tuple := loadConnectionConfigTuple()
	metadata, err := tuple.Auth.GetRequestMetadata(context.Background())
	if err != nil {
		return "", fmt.Errorf("connection metadata: %w", err)
	}
	observed := &model.AgentConfig{
		Server: tuple.Server, ClientSecret: metadata["client-secret"], UUID: metadata["client-uuid"],
		TLS: tuple.TLS, InsecureTLS: tuple.InsecureTLS,
	}
	for _, generation := range []integratedConfigGeneration{integratedGenerationA, integratedGenerationB} {
		expected := integratedGenerationConfig(generation)
		if observed.Server == expected.Server && observed.ClientSecret == expected.ClientSecret && observed.UUID == expected.UUID && observed.TLS == expected.TLS && observed.InsecureTLS == expected.InsecureTLS && tuple.Auth.RequireTransportSecurity() == expected.TLS {
			return generation, nil
		}
	}
	return "", fmt.Errorf("torn connection tuple: server=%q tls=%t insecure=%t metadata=%v requireTLS=%t", tuple.Server, tuple.TLS, tuple.InsecureTLS, metadata, tuple.Auth.RequireTransportSecurity())
}

func observeIntegratedDNS() (integratedConfigGeneration, error) {
	config := loadRuntimeConfig()
	generation, err := classifyIntegratedConfig(config)
	if err != nil {
		return "", err
	}
	if err := validateIntegratedDNSTuple(generation, dnsConfigTupleFrom(config)); err != nil {
		return "", err
	}
	return generation, nil
}

func validateIntegratedDNSTuple(generation integratedConfigGeneration, tuple dnsConfigTuple) error {
	expected := integratedGenerationConfig(generation)
	if !tuple.configured || len(tuple.servers) != 1 || tuple.servers[0] != expected.DNS[0] {
		return fmt.Errorf("torn DNS tuple: generation=%s configured=%t servers=%v", generation, tuple.configured, tuple.servers)
	}
	return nil
}

func validateIntegratedTaskGates(generation integratedConfigGeneration, gates taskFeatureGates) error {
	expected := integratedGenerationConfig(generation)
	if gates.disableForceUpdate != expected.DisableForceUpdate || gates.disableCommandExecute != expected.DisableCommandExecute || gates.disableNat != expected.DisableNat || gates.disableSendQuery != expected.DisableSendQuery {
		return fmt.Errorf("torn task gates for generation %s: %+v", generation, gates)
	}
	return nil
}

func observeIntegratedReportConfig() (integratedConfigGeneration, error) {
	snapshot := loadRuntimeConfig()
	generation, err := classifyIntegratedConfig(snapshot)
	if err != nil {
		return "", err
	}
	reportable := snapshot.Clone()
	reportable.DisableCommandExecute = false
	var result pb.TaskResult
	handleReportConfigTaskWithConfig(&reportable, &result)
	if !result.Successful {
		return "", fmt.Errorf("ReportConfig rejected: %q", result.Data)
	}
	var observed model.AgentConfig
	if err := json.Unmarshal([]byte(result.Data), &observed); err != nil {
		return "", fmt.Errorf("decode ReportConfig: %w", err)
	}
	expected := integratedGenerationConfig(generation)
	expected.DisableCommandExecute = false
	if !integratedConfigMatches(&observed, expected) {
		return "", fmt.Errorf("ReportConfig response does not match reportable generation %s: %+v", generation, observed)
	}
	return generation, nil
}

type integratedMonitorRecorder struct {
	mu       sync.Mutex
	expected *model.AgentConfig
	calls    map[string]int
	firstErr error
}

func (r *integratedMonitorRecorder) begin(config *model.AgentConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expected = config
	r.calls = make(map[string]int)
	r.firstErr = nil
}

func (r *integratedMonitorRecorder) record(name string, config *model.AgentConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[name]++
	if r.firstErr == nil && config != r.expected {
		r.firstErr = fmt.Errorf("monitor %s received different snapshot pointer", name)
	}
	if r.firstErr == nil {
		_, r.firstErr = classifyIntegratedConfig(config)
	}
}

func (r *integratedMonitorRecorder) recordState(config *model.AgentConfig, skipConnectionCount, skipProcsCount bool) {
	r.record("state", config)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.firstErr == nil && (skipConnectionCount != config.SkipConnectionCount || skipProcsCount != config.SkipProcsCount) {
		r.firstErr = fmt.Errorf("monitor state flags do not match caller snapshot: skipConnectionCount=%t skipProcsCount=%t", skipConnectionCount, skipProcsCount)
	}
}

func (r *integratedMonitorRecorder) recordFetch(config *model.AgentConfig, useIPv6CountryCode bool) {
	r.record("fetch", config)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.firstErr == nil && useIPv6CountryCode != config.UseIPv6CountryCode {
		r.firstErr = fmt.Errorf("monitor fetch flag does not match caller snapshot: useIPv6CountryCode=%t", useIPv6CountryCode)
	}
}

func (r *integratedMonitorRecorder) finish() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.firstErr != nil {
		return r.firstErr
	}
	for _, name := range []string{"track", "state", "host", "fetch"} {
		if r.calls[name] != 1 {
			return fmt.Errorf("monitor %s calls=%d, want 1", name, r.calls[name])
		}
	}
	return nil
}
