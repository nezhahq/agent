package main

import (
	"os"

	"github.com/nezhahq/service"
)

type AgentCliFlags struct {
	IsSpecified bool
	Flag        string
	Value       string
}

type program struct {
	exit    chan struct{}
	service service.Service
}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	if service.Interactive() {
		os.Exit(0)
	}
	return nil
}

func (p *program) run() {
	defer func() {
		if service.Interactive() {
			p.Stop(p.service)
		} else {
			p.service.Stop()
		}
	}()
	run()
}
