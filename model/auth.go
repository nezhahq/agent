package model

import (
	"context"
	"errors"
)

type AuthHandler struct {
	clientSecret             string
	clientUUID               string
	requireTransportSecurity bool
}

var ErrAuthCredentialsNotConfigured = errors.New("agent: AuthHandler credentials are not configured")

func NewAuthHandler(clientSecret, clientUUID string, requireTransportSecurity bool) *AuthHandler {
	return &AuthHandler{
		clientSecret:             clientSecret,
		clientUUID:               clientUUID,
		requireTransportSecurity: requireTransportSecurity,
	}
}

func (a *AuthHandler) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if a == nil || a.clientSecret == "" || a.clientUUID == "" {
		return nil, ErrAuthCredentialsNotConfigured
	}
	return map[string]string{
		"client-secret": a.clientSecret,
		"client-uuid":   a.clientUUID,
		"client_secret": a.clientSecret,
		"client_uuid":   a.clientUUID,
	}, nil
}

func (a *AuthHandler) RequireTransportSecurity() bool {
	if a == nil {
		return false
	}
	return a.requireTransportSecurity
}
