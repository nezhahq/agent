package main

import (
	"context"
	"errors"
	"io"
	"sync"

	pb "github.com/nezhahq/agent/proto"
)

type streamTaskRegistry struct {
	mu        sync.Mutex
	accepting bool
	active    int
	waitGroup sync.WaitGroup
}

func newStreamTaskRegistry() *streamTaskRegistry {
	return &streamTaskRegistry{accepting: true}
}

func (r *streamTaskRegistry) start(run func()) bool {
	r.mu.Lock()
	if !r.accepting {
		r.mu.Unlock()
		return false
	}
	r.active++
	r.waitGroup.Add(1)
	r.mu.Unlock()
	go func() {
		defer func() {
			r.mu.Lock()
			r.active--
			r.mu.Unlock()
			r.waitGroup.Done()
		}()
		run()
	}()
	return true
}

func (r *streamTaskRegistry) closeRegistration() {
	r.mu.Lock()
	r.accepting = false
	r.mu.Unlock()
}

func (r *streamTaskRegistry) wait() {
	r.waitGroup.Wait()
}

func (r *streamTaskRegistry) activeCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active
}

type connectionSession struct {
	streamContext        context.Context
	exitContext          context.Context
	longLivedTaskContext context.Context
	requestTaskContext   context.Context
	cancelStream         context.CancelCauseFunc
	requestExit          context.CancelCauseFunc
	cancelLongLivedTasks context.CancelCauseFunc
	cancelRequestTask    context.CancelCauseFunc
	daemons              sync.WaitGroup
	longLivedStreamTasks *streamTaskRegistry
	requestTask          *requestTaskSession
	reportState          *reportStateSession
}

type sessionShutdown struct {
	graceContext context.Context
	cause        error
}

func newConnectionSession(parent context.Context) *connectionSession {
	streamContext, cancelStream := context.WithCancelCause(parent)
	exitContext, requestExit := context.WithCancelCause(parent)
	longLivedTaskContext, cancelLongLivedTasks := context.WithCancelCause(parent)
	requestTaskContext, cancelRequestTask := context.WithCancelCause(streamContext)
	return &connectionSession{
		streamContext:        streamContext,
		exitContext:          exitContext,
		longLivedTaskContext: longLivedTaskContext,
		requestTaskContext:   requestTaskContext,
		cancelStream:         cancelStream,
		requestExit:          requestExit,
		cancelLongLivedTasks: cancelLongLivedTasks,
		cancelRequestTask:    cancelRequestTask,
		longLivedStreamTasks: newStreamTaskRegistry(),
	}
}

func (s *connectionSession) bindRequestTask(
	stream pb.NezhaService_RequestTaskClient,
) *requestTaskSession {
	requestSession := newRequestTaskSession(stream, s.cancelRequestTask)
	s.requestTask = requestSession
	return requestSession
}

func (s *connectionSession) newReportStateSession() *reportStateSession {
	return newReportStateSession(s.streamContext)
}

func (s *connectionSession) bindReportState(
	reportSession *reportStateSession,
	stream pb.NezhaService_ReportSystemStateClient,
) {
	reportSession.bind(stream)
	s.reportState = reportSession
}

func (s *connectionSession) startDaemon(run func()) {
	s.daemons.Go(run)
}

func (s *connectionSession) startLongLivedStreamTask(run func(context.Context)) bool {
	return s.longLivedStreamTasks.start(func() { run(s.longLivedTaskContext) })
}

func (s *connectionSession) signalExit(cause error) {
	s.requestExit(cause)
}

func (s *connectionSession) waitForDaemons() {
	s.daemons.Wait()
}

func (s *connectionSession) stopAndWait(graceContext context.Context, cause error) {
	if s.requestTask != nil {
		result := s.requestTask.prepareShutdown(graceContext)
		if result.Forced {
			printf("RequestTask forced shutdown: cause=%v, send=%v", result.Cause, result.Err)
		}
	}
	s.longLivedStreamTasks.closeRegistration()
	s.cancelLongLivedTasks(cause)
	s.longLivedStreamTasks.wait()
	if s.reportState != nil {
		result := s.reportState.shutdown(graceContext, cause)
		terminalErr, terminalForced := s.reportState.waitForTerminal(graceContext)
		if terminalErr != nil && !errors.Is(terminalErr, io.EOF) {
			result.Err = terminalErr
		}
		result.Forced = result.Forced || terminalForced
		if terminalForced && result.Cause == nil {
			result.Cause = context.Cause(graceContext)
		}
		if result.Forced {
			printf("ReportSystemState forced shutdown: cause=%v, send=%v", result.Cause, result.Err)
		} else if result.Err != nil {
			printf("ReportSystemState shutdown failed: %v", result.Err)
		}
	}
	if s.requestTask != nil {
		closeErr := s.requestTask.closeSendOnce()
		if closeErr != nil {
			printf("RequestTask shutdown failed: %v", closeErr)
		}
	}
	s.cancelStream(cause)
	s.waitForDaemons()
}

func reconnectAfterSessionExit(session *connectionSession, shutdown sessionShutdown, reconnect func()) {
	session.stopAndWait(shutdown.graceContext, shutdown.cause)
	reconnect()
}
