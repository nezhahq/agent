//go:build !agentcompat

package main

import "context"

func prepareFMSessionContext(ctx context.Context, _ string) (context.Context, func()) {
	return ctx, func() {}
}
