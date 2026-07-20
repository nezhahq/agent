package main

import (
	"context"
	"errors"
	"sync"

	pb "github.com/nezhahq/agent/proto"
)

var errRequestTaskSessionClosed = errors.New("RequestTask result stream is closed")

type requestTaskShutdownResult struct {
	Err    error
	Cause  error
	Forced bool
}

type requestTaskSession struct {
	stream       pb.NezhaService_RequestTaskClient
	cancelStream func(error)

	sendMu sync.Mutex

	stateMu     sync.Mutex
	accepting   bool
	activeDone  chan struct{}
	terminalErr error

	cancelOnce     sync.Once
	closeOnce      sync.Once
	prepareOnce    sync.Once
	shutdownOnce   sync.Once
	prepareResult  requestTaskShutdownResult
	shutdownResult requestTaskShutdownResult
}

func newRequestTaskSession(
	stream pb.NezhaService_RequestTaskClient,
	cancelStream func(error),
) *requestTaskSession {
	return &requestTaskSession{
		stream:       stream,
		cancelStream: cancelStream,
		accepting:    true,
	}
}

func (s *requestTaskSession) Context() context.Context { return s.stream.Context() }

func (s *requestTaskSession) Recv() (*pb.Task, error) { return s.stream.Recv() }

func (s *requestTaskSession) Send(result *pb.TaskResult) error {
	if err := s.rejectedSendError(); err != nil {
		return err
	}
	s.sendMu.Lock()

	s.stateMu.Lock()
	if !s.accepting {
		err := errors.Join(errRequestTaskSessionClosed, s.terminalErr)
		s.stateMu.Unlock()
		s.sendMu.Unlock()
		return err
	}
	activeDone := make(chan struct{})
	s.activeDone = activeDone
	s.stateMu.Unlock()

	err := s.stream.Send(result)

	s.stateMu.Lock()
	s.activeDone = nil
	if err != nil {
		s.accepting = false
		s.recordTerminalErrorLocked(err)
	}
	s.stateMu.Unlock()
	s.sendMu.Unlock()
	close(activeDone)
	if err != nil {
		s.cancel(err)
	}
	return err
}

func (s *requestTaskSession) shutdown(
	graceContext context.Context,
) requestTaskShutdownResult {
	s.shutdownOnce.Do(func() {
		prepared := s.prepareShutdown(graceContext)
		closeErr := s.closeSendOnce()
		s.shutdownResult = requestTaskShutdownResult{
			Err:    firstError(prepared.Err, closeErr),
			Cause:  prepared.Cause,
			Forced: prepared.Forced,
		}
	})
	return s.shutdownResult
}

func (s *requestTaskSession) prepareShutdown(graceContext context.Context) requestTaskShutdownResult {
	s.prepareOnce.Do(func() {
		activeDone, sendErr := s.beginClosing()
		forced, forcedCause := s.waitForActiveSend(graceContext, activeDone)
		if forced {
			s.cancel(forcedCause)
			if activeDone != nil {
				<-activeDone
			}
		}
		s.prepareResult = requestTaskShutdownResult{
			Err:    sendErr,
			Cause:  forcedCause,
			Forced: forced,
		}
	})
	return s.prepareResult
}

func (s *requestTaskSession) beginClosing() (<-chan struct{}, error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.accepting = false
	return s.activeDone, s.terminalErr
}

func (s *requestTaskSession) waitForActiveSend(
	graceContext context.Context,
	activeDone <-chan struct{},
) (bool, error) {
	if err := s.stream.Context().Err(); err != nil {
		return true, context.Cause(s.stream.Context())
	}
	if activeDone == nil {
		return false, nil
	}
	select {
	case <-activeDone:
		return false, nil
	case <-graceContext.Done():
		select {
		case <-activeDone:
			return false, nil
		default:
			return true, context.Cause(graceContext)
		}
	case <-s.stream.Context().Done():
		return true, context.Cause(s.stream.Context())
	}
}

func (s *requestTaskSession) closeSendOnce() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.closeOnce.Do(func() {
		err := s.stream.CloseSend()
		s.stateMu.Lock()
		s.recordTerminalErrorLocked(err)
		s.stateMu.Unlock()
		if err != nil {
			s.cancel(err)
		}
	})
	return s.terminalError()
}

func (s *requestTaskSession) rejectedSendError() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.accepting {
		return nil
	}
	return errors.Join(errRequestTaskSessionClosed, s.terminalErr)
}

func (s *requestTaskSession) terminalError() error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return s.terminalErr
}

func (s *requestTaskSession) recordTerminalErrorLocked(err error) {
	if s.terminalErr == nil && err != nil {
		s.terminalErr = err
	}
}

func (s *requestTaskSession) cancel(cause error) {
	s.cancelOnce.Do(func() { s.cancelStream(cause) })
}
