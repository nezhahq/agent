package main

import (
	"fmt"
	"testing"
	"time"
)

const streamFixtureDeadline = 3 * time.Second

func awaitStreamSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(streamFixtureDeadline):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func awaitStreamOperationResult[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(streamFixtureDeadline):
		t.Fatalf("timed out waiting for stream operation")
		var zero T
		return zero
	}
}

func assertStreamEvents(t *testing.T, got, want []string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("stream events = %v, want %v", got, want)
	}
}
