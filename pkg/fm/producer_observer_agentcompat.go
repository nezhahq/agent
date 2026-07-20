//go:build agentcompat

package fm

import (
	"context"
)

const fmProducerObserverContextKey = "github.com/nezhahq/agent/agentcompat/fm-producer-observer"

func observeProducerCount(ctx context.Context, active int64) {
	if observer, ok := ctx.Value(fmProducerObserverContextKey).(func(int64)); ok {
		observer(active)
	}
}
