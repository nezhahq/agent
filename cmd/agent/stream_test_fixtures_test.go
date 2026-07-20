package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

var errUnexpectedStreamCall = errors.New("unexpected stream fixture call")

var _ pb.NezhaService_RequestTaskClient = (*deterministicStreamFixture[pb.TaskResult, pb.Task])(nil)
var _ pb.NezhaService_ReportSystemStateClient = (*deterministicStreamFixture[pb.State, pb.Receipt])(nil)
var _ pb.NezhaService_IOStreamClient = (*deterministicStreamFixture[pb.IOStreamData, pb.IOStreamData])(nil)

type streamWriteOperation string

const (
	streamWriteSend      streamWriteOperation = "send"
	streamWriteCloseSend streamWriteOperation = "close_send"
)

type streamCallAllowance struct {
	send      int
	recv      int
	closeSend int
}

type streamObservation struct {
	events                      []string
	unexpectedCalls             []string
	maxWriteInFlight            int
	closeSendCount              int
	contextCancellationObserved bool
}

type streamRecvRelease[Res any] struct {
	message *Res
	err     error
}

type deterministicStreamFixture[Req, Res any] struct {
	ctx context.Context

	mu               chan struct{}
	allowance        streamCallAllowance
	events           []string
	unexpectedCalls  []string
	unexpectedCounts map[string]int
	sent             []*Req
	sendCount        int
	recvCount        int
	closeSendCount   int
	writeInFlight    int
	maxWriteInFlight int
	canceled         bool

	recvEntered  chan struct{}
	recvRelease  chan streamRecvRelease[Res]
	writeEntered chan streamWriteOperation
	sendRelease  chan error
	closeRelease chan error
}

func newDeterministicStreamFixture[Req, Res any](ctx context.Context, allowance streamCallAllowance) *deterministicStreamFixture[Req, Res] {
	fixture := &deterministicStreamFixture[Req, Res]{
		ctx:              ctx,
		mu:               make(chan struct{}, 1),
		allowance:        allowance,
		unexpectedCounts: make(map[string]int),
		recvEntered:      make(chan struct{}, max(allowance.recv, 1)),
		recvRelease:      make(chan streamRecvRelease[Res], max(allowance.recv, 1)),
		writeEntered:     make(chan streamWriteOperation, max(allowance.send+allowance.closeSend, 1)),
		sendRelease:      make(chan error, max(allowance.send, 1)),
		closeRelease:     make(chan error, max(allowance.closeSend, 1)),
	}
	fixture.mu <- struct{}{}
	return fixture
}

func newRequestTaskStreamFixture(ctx context.Context, allowance streamCallAllowance) *deterministicStreamFixture[pb.TaskResult, pb.Task] {
	return newDeterministicStreamFixture[pb.TaskResult, pb.Task](ctx, allowance)
}

func newReportSystemStateStreamFixture(ctx context.Context, allowance streamCallAllowance) *deterministicStreamFixture[pb.State, pb.Receipt] {
	return newDeterministicStreamFixture[pb.State, pb.Receipt](ctx, allowance)
}

func newIOStreamFixture(ctx context.Context, allowance streamCallAllowance) *deterministicStreamFixture[pb.IOStreamData, pb.IOStreamData] {
	return newDeterministicStreamFixture[pb.IOStreamData, pb.IOStreamData](ctx, allowance)
}

func (s *deterministicStreamFixture[Req, Res]) Send(message *Req) error {
	call, err := s.beginWrite(streamWriteSend)
	if err != nil {
		return err
	}
	s.lock()
	s.sent = append(s.sent, message)
	s.unlock()
	return s.finishWrite(streamWriteSend, call)
}

func (s *deterministicStreamFixture[Req, Res]) Recv() (*Res, error) {
	s.lock()
	s.recvCount++
	call := s.recvCount
	if call > s.allowance.recv {
		err := s.recordUnexpectedLocked("recv")
		s.unlock()
		return nil, err
	}
	s.events = append(s.events, fmt.Sprintf("recv:start:%d", call))
	s.unlock()
	s.recvEntered <- struct{}{}

	select {
	case release := <-s.recvRelease:
		s.recordEvent(fmt.Sprintf("recv:end:%d", call))
		return release.message, release.err
	case <-s.ctx.Done():
		s.recordCancellation(fmt.Sprintf("recv:canceled:%d", call))
		return nil, s.ctx.Err()
	}
}

func (s *deterministicStreamFixture[Req, Res]) CloseSend() error {
	call, err := s.beginWrite(streamWriteCloseSend)
	if err != nil {
		return err
	}
	return s.finishWrite(streamWriteCloseSend, call)
}

func (s *deterministicStreamFixture[Req, Res]) Header() (metadata.MD, error) {
	return nil, s.recordUnexpected("header")
}

func (s *deterministicStreamFixture[Req, Res]) Trailer() metadata.MD {
	s.recordUnexpected("trailer")
	return nil
}

func (s *deterministicStreamFixture[Req, Res]) Context() context.Context { return s.ctx }

func (s *deterministicStreamFixture[Req, Res]) SendMsg(any) error {
	return s.recordUnexpected("send_msg")
}

func (s *deterministicStreamFixture[Req, Res]) RecvMsg(any) error {
	return s.recordUnexpected("recv_msg")
}

func (s *deterministicStreamFixture[Req, Res]) beginWrite(operation streamWriteOperation) (int, error) {
	s.lock()
	var call int
	var allowed int
	switch operation {
	case streamWriteSend:
		s.sendCount++
		call, allowed = s.sendCount, s.allowance.send
	case streamWriteCloseSend:
		s.closeSendCount++
		call, allowed = s.closeSendCount, s.allowance.closeSend
	}
	if call > allowed {
		err := s.recordUnexpectedCallLocked(string(operation), call)
		s.unlock()
		return call, err
	}
	s.writeInFlight++
	if s.writeInFlight > s.maxWriteInFlight {
		s.maxWriteInFlight = s.writeInFlight
	}
	s.events = append(s.events, fmt.Sprintf("%s:start:%d", operation, call))
	s.unlock()
	s.writeEntered <- operation
	return call, nil
}

func (s *deterministicStreamFixture[Req, Res]) finishWrite(operation streamWriteOperation, call int) error {
	var release <-chan error
	switch operation {
	case streamWriteSend:
		release = s.sendRelease
	case streamWriteCloseSend:
		release = s.closeRelease
	}
	select {
	case err := <-release:
		s.lock()
		s.writeInFlight--
		s.events = append(s.events, fmt.Sprintf("%s:end:%d", operation, call))
		s.unlock()
		return err
	case <-s.ctx.Done():
		s.lock()
		s.writeInFlight--
		s.canceled = true
		s.events = append(s.events, fmt.Sprintf("%s:canceled:%d", operation, call))
		s.unlock()
		return s.ctx.Err()
	}
}

func (s *deterministicStreamFixture[Req, Res]) waitRecvEntered(t *testing.T) {
	t.Helper()
	awaitStreamSignal(t, s.recvEntered, "Recv entry")
}

func (s *deterministicStreamFixture[Req, Res]) releaseRecv(message *Res, err error) {
	s.recvRelease <- streamRecvRelease[Res]{message: message, err: err}
}

func (s *deterministicStreamFixture[Req, Res]) waitWriteEntered(t *testing.T, operation streamWriteOperation) {
	t.Helper()
	entered := awaitStreamOperationResult(t, s.writeEntered)
	if entered != operation {
		t.Fatalf("write operation = %q, want %q", entered, operation)
	}
}

func (s *deterministicStreamFixture[Req, Res]) releaseWrite(operation streamWriteOperation, err error) {
	switch operation {
	case streamWriteSend:
		s.sendRelease <- err
	case streamWriteCloseSend:
		s.closeRelease <- err
	}
}

func (s *deterministicStreamFixture[Req, Res]) observe() streamObservation {
	s.lock()
	defer s.unlock()
	return streamObservation{
		events:                      append([]string(nil), s.events...),
		unexpectedCalls:             append([]string(nil), s.unexpectedCalls...),
		maxWriteInFlight:            s.maxWriteInFlight,
		closeSendCount:              s.closeSendCount,
		contextCancellationObserved: s.canceled,
	}
}

func (s *deterministicStreamFixture[Req, Res]) sentMessages() []*Req {
	s.lock()
	defer s.unlock()
	return append([]*Req(nil), s.sent...)
}

func (s *deterministicStreamFixture[Req, Res]) recordUnexpected(name string) error {
	s.lock()
	defer s.unlock()
	return s.recordUnexpectedLocked(name)
}

func (s *deterministicStreamFixture[Req, Res]) recordUnexpectedLocked(name string) error {
	s.unexpectedCounts[name]++
	call := s.unexpectedCounts[name]
	return s.recordUnexpectedCallLocked(name, call)
}

func (s *deterministicStreamFixture[Req, Res]) recordUnexpectedCallLocked(name string, call int) error {
	s.unexpectedCalls = append(s.unexpectedCalls, fmt.Sprintf("%s:%d", name, call))
	return fmt.Errorf("%w: %s call %d", errUnexpectedStreamCall, name, call)
}

func (s *deterministicStreamFixture[Req, Res]) recordEvent(event string) {
	s.lock()
	s.events = append(s.events, event)
	s.unlock()
}

func (s *deterministicStreamFixture[Req, Res]) recordCancellation(event string) {
	s.lock()
	s.canceled = true
	s.events = append(s.events, event)
	s.unlock()
}

func (s *deterministicStreamFixture[Req, Res]) lock()   { <-s.mu }
func (s *deterministicStreamFixture[Req, Res]) unlock() { s.mu <- struct{}{} }
