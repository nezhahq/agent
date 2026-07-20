//go:build agentcompat

package main

import (
	"context"
	"sync/atomic"
)

const fmProducerObserverContextKey = "github.com/nezhahq/agent/agentcompat/fm-producer-observer"

func prepareFMSessionContext(ctx context.Context, sessionID string) (context.Context, func()) {
	var activeCount atomic.Int64
	observerContext := context.WithValue(ctx, fmProducerObserverContextKey, func(active int64) {
		activeCount.Store(active)
		phase := "active"
		if active == 0 {
			phase = "idle"
		}
		observeFMProducer(sessionID, phase, active)
	})
	return observerContext, func() {
		observeFMProducer(sessionID, "closed", activeCount.Load())
	}
}
