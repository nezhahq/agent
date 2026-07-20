package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

type contextBlockedReportStateStream struct {
	ctx context.Context

	mu                 sync.Mutex
	events             []string
	writeInFlight      int
	maxInFlight        int
	closeCount         int
	contextLiveAtClose bool
	sendStarted        chan struct{}
}

func newContextBlockedReportStateStream(ctx context.Context) *contextBlockedReportStateStream {
	return &contextBlockedReportStateStream{ctx: ctx, sendStarted: make(chan struct{})}
}

func (s *contextBlockedReportStateStream) Send(*pb.State) error {
	s.beginWrite("send:start")
	close(s.sendStarted)
	<-s.ctx.Done()
	s.finishWrite("stream:cancel", "send:context_done")
	return context.Cause(s.ctx)
}

func (s *contextBlockedReportStateStream) CloseSend() error {
	s.beginWrite("close:start")
	s.mu.Lock()
	s.closeCount++
	s.contextLiveAtClose = s.ctx.Err() == nil
	s.mu.Unlock()
	s.finishWrite("close:end")
	return nil
}

func (s *contextBlockedReportStateStream) Recv() (*pb.Receipt, error) {
	<-s.ctx.Done()
	return nil, context.Cause(s.ctx)
}

func (s *contextBlockedReportStateStream) Header() (metadata.MD, error) { return nil, nil }
func (s *contextBlockedReportStateStream) Trailer() metadata.MD         { return nil }
func (s *contextBlockedReportStateStream) Context() context.Context     { return s.ctx }
func (s *contextBlockedReportStateStream) SendMsg(any) error            { return nil }
func (s *contextBlockedReportStateStream) RecvMsg(any) error            { return nil }

func (s *contextBlockedReportStateStream) beginWrite(event string) {
	s.mu.Lock()
	s.writeInFlight++
	if s.writeInFlight > s.maxInFlight {
		s.maxInFlight = s.writeInFlight
	}
	s.events = append(s.events, event)
	s.mu.Unlock()
}

func (s *contextBlockedReportStateStream) finishWrite(events ...string) {
	s.mu.Lock()
	s.writeInFlight--
	s.events = append(s.events, events...)
	s.mu.Unlock()
}

func (s *contextBlockedReportStateStream) observation() ([]string, int, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...), s.maxInFlight, s.closeCount, s.contextLiveAtClose
}

func TestReportStateSendClose_ShutdownSelfReleasesContextBlockedSend(t *testing.T) {
	// Given
	reportSession := newReportStateSession(context.Background())
	stream := newContextBlockedReportStateStream(reportSession.streamContext)
	reportSession.bind(stream)
	sendExited := make(chan error, 1)
	go func() { sendExited <- reportSession.Send(&pb.State{}) }()
	awaitStreamSignal(t, stream.sendStarted, "context-blocked ReportState Send entry")
	graceContext, cancelGrace := context.WithCancel(context.Background())
	shutdownExited := make(chan reportStateShutdownResult, 1)

	// When
	go func() { shutdownExited <- reportSession.shutdown(graceContext, context.Canceled) }()
	cancelGrace()
	shutdownResult := awaitStreamOperationResult(t, shutdownExited)

	// Then
	if !shutdownResult.Forced || !errors.Is(shutdownResult.Cause, context.Canceled) {
		t.Fatalf("forced shutdown result = %+v, want forced context.Canceled", shutdownResult)
	}
	sendErr := awaitStreamOperationResult(t, sendExited)
	if !errors.Is(sendErr, context.Canceled) || !errors.Is(shutdownResult.Err, context.Canceled) {
		t.Fatalf("forced errors: send=%v shutdown=%v, want context.Canceled", sendErr, shutdownResult.Err)
	}
	events, maxInFlight, closeCount, contextLiveAtClose := stream.observation()
	assertStreamEvents(t, events, []string{"send:start", "stream:cancel", "send:context_done", "close:start", "close:end"})
	if maxInFlight != 1 || closeCount != 1 {
		t.Fatalf("forced shutdown writes: max=%d close=%d, want max=1 close=1", maxInFlight, closeCount)
	}
	if contextLiveAtClose {
		t.Fatal("forced CloseSend observed a live stream context")
	}
}

func TestReportStateSendClose_ParentCancelSelfReleasesContextBlockedSend(t *testing.T) {
	// Given
	parent, cancelParent := context.WithCancel(context.Background())
	reportSession := newReportStateSession(parent)
	stream := newContextBlockedReportStateStream(reportSession.streamContext)
	reportSession.bind(stream)
	sendExited := make(chan error, 1)
	go func() { sendExited <- reportSession.Send(&pb.State{}) }()
	awaitStreamSignal(t, stream.sendStarted, "parent-cancel blocked Send entry")

	// When
	cancelParent()
	result := reportSession.shutdown(context.Background(), context.Canceled)

	// Then
	if !result.Forced || !errors.Is(result.Cause, context.Canceled) {
		t.Fatalf("parent-cancel shutdown result = %+v, want forced context.Canceled", result)
	}
	if err := awaitStreamOperationResult(t, sendExited); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent-cancel Send error = %v, want context.Canceled", err)
	}
	events, maxInFlight, closeCount, contextLiveAtClose := stream.observation()
	assertStreamEvents(t, events, []string{"send:start", "stream:cancel", "send:context_done", "close:start", "close:end"})
	if maxInFlight != 1 || closeCount != 1 || contextLiveAtClose {
		t.Fatalf("parent-cancel writes: max=%d close=%d liveAtClose=%t", maxInFlight, closeCount, contextLiveAtClose)
	}
}

func TestReportStateSendClose_BeginClosingRejectsQueuedSend(t *testing.T) {
	// Given
	reportSession := newReportStateSession(context.Background())
	stream := newContextBlockedReportStateStream(reportSession.streamContext)
	reportSession.bind(stream)
	firstSendExited := make(chan error, 1)
	go func() { firstSendExited <- reportSession.Send(&pb.State{}) }()
	awaitStreamSignal(t, stream.sendStarted, "first blocked ReportState Send entry")
	activeDone, _ := reportSession.owner.beginClosing()
	secondSendExited := make(chan error, 1)
	go func() { secondSendExited <- reportSession.Send(&pb.State{}) }()

	// When
	secondErr := awaitStreamOperationResult(t, secondSendExited)
	reportSession.cancelStream(context.Canceled)
	<-activeDone
	firstErr := awaitStreamOperationResult(t, firstSendExited)

	// Then
	if !errors.Is(firstErr, context.Canceled) {
		t.Fatalf("first Send error = %v, want context.Canceled", firstErr)
	}
	if !errors.Is(secondErr, errReportStateWriteClosed) {
		t.Fatalf("queued Send error = %v, want %v", secondErr, errReportStateWriteClosed)
	}
	events, maxInFlight, closeCount, _ := stream.observation()
	assertStreamEvents(t, events, []string{"send:start", "stream:cancel", "send:context_done"})
	if maxInFlight != 1 || closeCount != 0 {
		t.Fatalf("beginClosing writes: max=%d close=%d, want max=1 close=0", maxInFlight, closeCount)
	}
}
