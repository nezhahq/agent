//go:build !darwin

package logger

import (
	"github.com/nezhahq/service"
)

func NewNezhaServiceLogger(s service.Service, errs chan<- error) (service.Logger, error) {
	return s.Logger(errs)
}
