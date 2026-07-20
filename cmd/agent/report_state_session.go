package main

import (
	"context"
	"sync"

	pb "github.com/nezhahq/agent/proto"
)

type reportStateShutdownResult struct {
	Err    error
	Cause  error
	Forced bool
}

type reportStateSession struct {
	streamContext  context.Context
	cadenceContext context.Context
	cancelStream   context.CancelCauseFunc
	stopCadence    context.CancelFunc

	stream pb.NezhaService_ReportSystemStateClient
	owner  *reportStateWriteOwner

	terminalDone chan struct{}
	terminalOnce sync.Once
	terminalMu   sync.Mutex
	terminalErr  error

	shutdownOnce   sync.Once
	shutdownResult reportStateShutdownResult
}

func newReportStateSession(parent context.Context) *reportStateSession {
	streamContext, cancelStream := context.WithCancelCause(parent)
	cadenceContext, stopCadence := context.WithCancel(streamContext)
	return &reportStateSession{
		streamContext:  streamContext,
		cadenceContext: cadenceContext,
		cancelStream:   cancelStream,
		stopCadence:    stopCadence,
		terminalDone:   make(chan struct{}),
	}
}

func (s *reportStateSession) finishTerminal(err error) {
	s.terminalOnce.Do(func() {
		s.terminalMu.Lock()
		s.terminalErr = err
		s.terminalMu.Unlock()
		close(s.terminalDone)
	})
}

func (s *reportStateSession) terminalError() error {
	<-s.terminalDone
	s.terminalMu.Lock()
	defer s.terminalMu.Unlock()
	return s.terminalErr
}

func (s *reportStateSession) waitForTerminal(graceContext context.Context) (error, bool) {
	select {
	case <-s.terminalDone:
		return s.terminalError(), false
	case <-graceContext.Done():
		select {
		case <-s.terminalDone:
			return s.terminalError(), false
		default:
		}
		s.cancelStream(context.Cause(graceContext))
		<-s.terminalDone
		return s.terminalError(), true
	}
}

func (s *reportStateSession) bind(stream pb.NezhaService_ReportSystemStateClient) {
	s.stream = stream
	s.owner = newReportStateWriteOwner(stream)
}

func (s *reportStateSession) Context() context.Context { return s.streamContext }

func (s *reportStateSession) Send(state *pb.State) error { return s.owner.Send(state) }

func (s *reportStateSession) Recv() (*pb.Receipt, error) { return s.stream.Recv() }

func (s *reportStateSession) shutdown(graceContext context.Context, cause error) reportStateShutdownResult {
	s.shutdownOnce.Do(func() {
		s.stopCadence()
		activeDone, sendErr := s.owner.beginClosing()
		forced, forcedCause := s.waitForActiveSend(graceContext, activeDone)
		if forced {
			s.cancelStream(forcedCause)
			if activeDone != nil {
				<-activeDone
			}
		}
		closeErr := s.owner.closeSendOnce()
		// On a graceful close, keep the receive side alive so grpc-go can consume
		// the peer's terminal status and trailers. The owning connectionSession
		// cancels the shared parent after every stream has sent END_STREAM.
		s.shutdownResult = reportStateShutdownResult{
			Err:    firstError(sendErr, closeErr),
			Cause:  forcedCause,
			Forced: forced,
		}
	})
	return s.shutdownResult
}

func (s *reportStateSession) waitForActiveSend(graceContext context.Context, activeDone <-chan struct{}) (bool, error) {
	if err := s.streamContext.Err(); err != nil {
		return true, context.Cause(s.streamContext)
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
	case <-s.streamContext.Done():
		return true, context.Cause(s.streamContext)
	}
}

func firstError(errorsToCheck ...error) error {
	for _, err := range errorsToCheck {
		if err != nil {
			return err
		}
	}
	return nil
}
