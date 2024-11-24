package logger

import (
	"fmt"
	"sync"
	"time"

	"github.com/nezhahq/service"
)

var (
	DefaultLogger = &ServiceLogger{enabled: true, logger: service.ConsoleLogger}

	loggerOnce sync.Once
)

type ServiceLogger struct {
	enabled bool
	logger  service.Logger
}

func InitDefaultLogger(enabled bool, logger service.Logger) {
	loggerOnce.Do(func() {
		DefaultLogger = &ServiceLogger{
			enabled: enabled,
			logger:  logger,
		}
	})
}

func NewServiceLogger(enable bool, logger service.Logger) *ServiceLogger {
	return &ServiceLogger{
		enabled: enable,
		logger:  logger,
	}
}

func (s *ServiceLogger) Println(v ...interface{}) {
	if s.enabled {
		s.logger.Infof("NEZHA@%s>> %v", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(v...))
	}
}

func (s *ServiceLogger) Printf(format string, v ...interface{}) {
	if s.enabled {
		s.logger.Infof("NEZHA@%s>> "+format, append([]interface{}{time.Now().Format("2006-01-02 15:04:05")}, v...)...)
	}
}

func (s *ServiceLogger) Error(v ...interface{}) error {
	if s.enabled {
		return s.logger.Errorf("NEZHA@%s>> %v", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(v...))
	}
	return nil
}

func (s *ServiceLogger) Errorf(format string, v ...interface{}) error {
	if s.enabled {
		return s.logger.Errorf("NEZHA@%s>> "+format, append([]interface{}{time.Now().Format("2006-01-02 15:04:05")}, v...)...)
	}
	return nil
}
