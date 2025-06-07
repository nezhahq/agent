//go:build darwin

package logger

import (
	"github.com/nezhahq/service"
)

type serviceLogger struct {
	service.Logger
}

// darwin will ignore info level logs by default
func (s *serviceLogger) Info(v ...any) error {
	return s.Warning(v...)
}

func (s *serviceLogger) Infof(format string, v ...any) error {
	return s.Warningf(format, v...)
}

func NewNezhaServiceLogger(s service.Service, errs chan<- error) (service.Logger, error) {
	logger, err := s.Logger(errs)
	if err != nil {
		return nil, err
	}

	return &serviceLogger{logger}, nil
}
