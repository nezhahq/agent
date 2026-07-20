//go:build !agentcompat

package fm

import "context"

func observeProducerCount(context.Context, int64) {}
