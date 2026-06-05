package model

import (
	"context"
	"errors"
)

// AuthHandler attaches the agent's identity to every outbound gRPC call.
// Credentials is a single closure returning a coherent (secret, uuid) pair so
// a dashboard-initiated rotation (server transfer / ownership swap) cannot be
// observed mid-swap as a torn (oldUUID, newSecret) pair. Each gRPC dial calls
// Credentials once; a save-first-then-publish reload in the agent is enough
// to switch credentials atomically.
type AuthHandler struct {
	Credentials func() (secret, uuid string)
	// RequireTLS reports whether the agent's transport must be encrypted, read
	// from the live agent config so plaintext intranet deployments (TLS:false)
	// keep working while TLS-enabled agents refuse to leak credentials over a
	// cleartext channel. nil means "do not require TLS" (legacy behaviour).
	RequireTLS func() bool
}

// ErrAuthCredentialsNotConfigured surfaces from gRPC dial metadata when an
// AuthHandler has been constructed without a Credentials closure (e.g. zero
// value, or a refactor that forgot to wire publishCredentials). Returning an
// error instead of panicking keeps the gRPC client loop alive so the
// supervisor can log and retry — a nil dereference would crash the agent
// process and cause unattended hosts to flap.
var ErrAuthCredentialsNotConfigured = errors.New("agent: AuthHandler.Credentials closure is not configured")

func (a *AuthHandler) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if a == nil || a.Credentials == nil {
		return nil, ErrAuthCredentialsNotConfigured
	}
	secret, uuid := a.Credentials()
	return map[string]string{
		"client-secret": secret,
		"client-uuid":   uuid,
		"client_secret": secret,
		"client_uuid":   uuid,
	}, nil
}

func (a *AuthHandler) RequireTransportSecurity() bool {
	if a == nil || a.RequireTLS == nil {
		return false
	}
	return a.RequireTLS()
}
