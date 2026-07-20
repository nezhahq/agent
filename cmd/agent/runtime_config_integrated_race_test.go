package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

const integratedRaceObservations = 130

func TestRuntimeConfigIntegratedWriterReadersObserveOnlyCompleteGenerations(t *testing.T) {
	// Given
	restoreIntegratedRaceGlobals(t)
	generationA := integratedGenerationConfig(integratedGenerationA)
	generationB := integratedGenerationConfig(integratedGenerationB)
	commitIntegratedReload(t, generationA, generationB)
	recorder := &integratedMonitorRecorder{}
	installIntegratedMonitorDependencies(t, recorder)
	lanes := integratedRaceLanes(recorder)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := make(chan struct{})
	acknowledged := make(chan struct{}, integratedRaceObservations*len(lanes))
	summaries := make(chan integratedRaceSummary, len(lanes))
	failures := make(chan error, 1)
	var wait sync.WaitGroup
	wait.Add(len(lanes) + 1)
	coordinator := integratedRaceCoordinator{
		ctx:          ctx,
		start:        start,
		acknowledged: acknowledged,
		summaries:    summaries,
		failures:     failures,
		wait:         &wait,
	}

	// When
	for _, lane := range lanes {
		go coordinator.runReader(lane)
	}
	go coordinator.runWriter(lanes)
	close(start)
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		cancel()
		shutdownTimer := time.NewTimer(5 * time.Second)
		defer shutdownTimer.Stop()
		select {
		case <-done:
		case <-shutdownTimer.C:
			t.Fatal("integrated runtime config race cancellation did not join goroutines within 5s")
		}
		t.Fatal("integrated runtime config race did not complete within 15s")
	}
	close(summaries)

	// Then
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	for summary := range summaries {
		if summary.total < 100 {
			t.Fatalf("%s completed observations=%d, want at least 100", summary.name, summary.total)
		}
		if summary.generation[integratedGenerationA] == 0 || summary.generation[integratedGenerationB] == 0 {
			t.Fatalf("%s observations did not include both generations: A=%d B=%d", summary.name, summary.generation[integratedGenerationA], summary.generation[integratedGenerationB])
		}
		t.Logf("lane=%s observations=%d generationA=%d generationB=%d", summary.name, summary.total, summary.generation[integratedGenerationA], summary.generation[integratedGenerationB])
	}
}

func integratedRaceLanes(recorder *integratedMonitorRecorder) []integratedRaceLane {
	return []integratedRaceLane{
		{name: "connection-auth", trigger: make(chan struct{}), observe: observeIntegratedConnection},
		{name: "dns", trigger: make(chan struct{}), observe: observeIntegratedDNS},
		{name: "report-tuple", trigger: make(chan struct{}), observe: func() (integratedConfigGeneration, error) {
			tuple := reportConfigTupleFrom(loadRuntimeConfig())
			generation, err := classifyIntegratedConfig(tuple.snapshot)
			if err != nil {
				return "", err
			}
			expected := integratedGenerationConfig(generation)
			if tuple.reportDelay != expected.ReportDelay || tuple.ipReportPeriod != expected.IPReportPeriod || tuple.skipConnectionCount != expected.SkipConnectionCount || tuple.skipProcsCount != expected.SkipProcsCount || tuple.useIPv6CountryCode != expected.UseIPv6CountryCode {
				return "", fmt.Errorf("torn report tuple for generation %s: %+v", generation, tuple)
			}
			return generation, nil
		}},
		{name: "task-gates", trigger: make(chan struct{}), observe: func() (integratedConfigGeneration, error) {
			config := loadRuntimeConfig()
			gates := taskFeatureGatesFrom(config)
			generation, err := classifyIntegratedConfig(config)
			if err != nil {
				return "", err
			}
			if err := validateIntegratedTaskGates(generation, gates); err != nil {
				return "", err
			}
			return generation, nil
		}},
		{name: "report-config", trigger: make(chan struct{}), observe: observeIntegratedReportConfig},
		{name: "top-level-report-monitor", trigger: make(chan struct{}), observe: func() (integratedConfigGeneration, error) {
			config := reportConfigTupleFrom(loadRuntimeConfig())
			generation, err := classifyIntegratedConfig(config.snapshot)
			if err != nil {
				return "", err
			}
			recorder.begin(config.snapshot)
			geoipReported = false
			_, err = reportState(&snapshotReportStateStream{ctx: context.Background()}, reportSchedule{}, config)
			if err != nil {
				return "", fmt.Errorf("top-level report: %w", err)
			}
			return generation, recorder.finish()
		}},
	}
}

func TestIntegratedDNSValidatorRejectsUnconfiguredTuple(t *testing.T) {
	config := integratedGenerationConfig(integratedGenerationA)
	tuple := dnsConfigTupleFrom(&config)
	tuple.configured = false

	if err := validateIntegratedDNSTuple(integratedGenerationA, tuple); err == nil {
		t.Fatal("DNS validator accepted configured=false for a configured generation")
	}
}

func TestIntegratedTaskGateValidatorRejectsEveryCrossGenerationField(t *testing.T) {
	a := integratedGenerationConfig(integratedGenerationA)
	b := integratedGenerationConfig(integratedGenerationB)
	if taskFeatureGatesFrom(&a) == taskFeatureGatesFrom(&b) {
		t.Fatal("task gate generations must differ in every field")
	}

	for name, mutate := range map[string]func(*taskFeatureGates){
		"force-update": func(gates *taskFeatureGates) { gates.disableForceUpdate = b.DisableForceUpdate },
		"command":      func(gates *taskFeatureGates) { gates.disableCommandExecute = b.DisableCommandExecute },
		"nat":          func(gates *taskFeatureGates) { gates.disableNat = b.DisableNat },
		"query":        func(gates *taskFeatureGates) { gates.disableSendQuery = b.DisableSendQuery },
	} {
		t.Run(name, func(t *testing.T) {
			gates := taskFeatureGatesFrom(&a)
			mutate(&gates)
			if err := validateIntegratedTaskGates(integratedGenerationA, gates); err == nil {
				t.Fatalf("task gate validator accepted generation B %s field in generation A", name)
			}
		})
	}
}

func (c integratedRaceCoordinator) runReader(lane integratedRaceLane) {
	defer c.wait.Done()
	summary := integratedRaceSummary{name: lane.name, generation: make(map[integratedConfigGeneration]int)}
	defer func() { c.summaries <- summary }()
	select {
	case <-c.start:
	case <-c.ctx.Done():
		return
	}
	for {
		select {
		case <-c.ctx.Done():
			return
		case _, open := <-lane.trigger:
			if !open {
				return
			}
		}
		generation, err := lane.observe()
		if err != nil {
			select {
			case c.failures <- fmt.Errorf("%s observation %d: %w", lane.name, summary.total+1, err):
			default:
			}
		} else {
			summary.generation[generation]++
		}
		summary.total++
		select {
		case c.acknowledged <- struct{}{}:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c integratedRaceCoordinator) runWriter(lanes []integratedRaceLane) {
	defer c.wait.Done()
	defer func() {
		for _, lane := range lanes {
			close(lane.trigger)
		}
	}()
	select {
	case <-c.start:
	case <-c.ctx.Done():
		return
	}
	for observation := 0; observation < integratedRaceObservations; observation++ {
		generation := integratedGenerationA
		if observation%2 == 1 {
			generation = integratedGenerationB
		}
		source := integratedGenerationConfig(generation)
		publishRuntimeConfig(source)
		mutateIntegratedGenerationSource(&source)
		for _, lane := range lanes {
			select {
			case lane.trigger <- struct{}{}:
			case <-c.ctx.Done():
				return
			}
		}
		if observation < 2 {
			for range lanes {
				select {
				case <-c.acknowledged:
				case <-c.ctx.Done():
					return
				}
			}
		}
	}
}
