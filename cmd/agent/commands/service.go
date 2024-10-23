package commands

import (
	"os"

	"github.com/nezhahq/service"
)

type Program struct {
	Exit    chan struct{}
	Service service.Service
	Run     func()
}

func (p *Program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *Program) Stop(s service.Service) error {
	close(p.Exit)
	if service.Interactive() {
		os.Exit(0)
	}
	return nil
}

func (p *Program) run() {
	defer func() {
		if service.Interactive() {
			p.Stop(p.Service)
		} else {
			p.Service.Stop()
		}
	}()
	p.Run()
}
