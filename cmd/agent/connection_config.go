package main

import (
	"crypto/tls"

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
			tlsConfig.InsecureSkipVerify = true
		}
		securityOption = grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	} else {
		securityOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	return []grpc.DialOption{securityOption, grpc.WithPerRPCCredentials(c.Auth)}
}
