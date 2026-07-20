package logger

import (
	"sync"
	"testing"
)

type concurrentTestLogger struct{}

func (concurrentTestLogger) Error(...interface{}) error            { return nil }
func (concurrentTestLogger) Warning(...interface{}) error          { return nil }
func (concurrentTestLogger) Info(...interface{}) error             { return nil }
func (concurrentTestLogger) Errorf(string, ...interface{}) error   { return nil }
func (concurrentTestLogger) Warningf(string, ...interface{}) error { return nil }
func (concurrentTestLogger) Infof(string, ...interface{}) error    { return nil }

func TestServiceLogger_SetEnableIsSafeDuringConcurrentLogging(t *testing.T) {
	// Given
	logger := NewServiceLogger(true, concurrentTestLogger{})
	const iterations = 1_000
	var workers sync.WaitGroup
	workers.Add(2)

	// When
	go func() {
		defer workers.Done()
		for index := range iterations {
			logger.SetEnable(index%2 == 0)
		}
	}()
	go func() {
		defer workers.Done()
		for range iterations {
			logger.Printf("concurrent log")
		}
	}()
	workers.Wait()

	// Then
	logger.SetEnable(true)
	if err := logger.Errorf("final log"); err != nil {
		t.Fatalf("Errorf() = %v, want nil", err)
	}
}
