package model

import (
	"context"
)

type AuthHandler struct {
	ClientSecret string
	ClientUUID   string
}

func (a *AuthHandler) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"client_secret": a.ClientSecret, "client_uuid": a.ClientUUID}, nil
}

func (a *AuthHandler) RequireTransportSecurity() bool {
	return false
}
