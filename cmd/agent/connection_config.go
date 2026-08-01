package main

import (
	"crypto/tls"
	"log"

	"github.com/nezhahq/agent/model"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type connectionConfigTuple struct {
	Server      string
	TLS         bool
	InsecureTLS bool
	Auth        *model.AuthHandler
}

func loadConnectionConfigTuple() connectionConfigTuple {
	// Load once: transport and per-RPC credentials must belong to one generation,
	// otherwise a plaintext connection could receive a newly rotated secret.
	config := loadRuntimeConfig()
	return connectionConfigTuple{
		Server:      config.Server,
		TLS:         config.TLS,
		InsecureTLS: config.InsecureTLS,
		Auth:        model.NewAuthHandler(config.ClientSecret, config.UUID, config.TLS),
	}
}

func (c connectionConfigTuple) dialOptions() []grpc.DialOption {
	var securityOption grpc.DialOption
	if c.TLS {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if c.InsecureTLS {
			// InsecureSkipVerify disables TLS certificate verification.
			// This exposes the connection to man-in-the-middle attacks and
			// should only be used in trusted environments or during testing.
			log.Println("WARNING: TLS certificate verification is disabled (insecure_tls=true). Use only in trusted environments.")
			tlsConfig.InsecureSkipVerify = true // #nosec G402 -- user explicitly opted in; logged above
		}
		securityOption = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	} else {
		securityOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	return []grpc.DialOption{securityOption, grpc.WithPerRPCCredentials(c.Auth)}
}
