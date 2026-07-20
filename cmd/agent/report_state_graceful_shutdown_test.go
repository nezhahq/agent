package main

import (
	"context"
	"sync"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

type gracefulReportStateStream struct {
	ctx context.Context

	mu                 sync.Mutex
	events             []string
	contextLiveAtClose bool
	closeCount         int
}

func (s *gracefulReportStateStream) Send(*pb.State) error {
	s.record("send:start", "send:end")
	return nil
}

func (s *gracefulReportStateStream) CloseSend() error {
	s.mu.Lock()
	s.events = append(s.events, "close:start")
	s.contextLiveAtClose = s.ctx.Err() == nil
	s.closeCount++
	s.events = append(s.events, "close:end")
	s.mu.Unlock()
	return nil
}

func (s *gracefulReportStateStream) Recv() (*pb.Receipt, error)   { return nil, nil }
func (s *gracefulReportStateStream) Header() (metadata.MD, error) { return nil, nil }
func (s *gracefulReportStateStream) Trailer() metadata.MD         { return nil }
func (s *gracefulReportStateStream) Context() context.Context     { return s.ctx }
func (s *gracefulReportStateStream) SendMsg(any) error            { return nil }
func (s *gracefulReportStateStream) RecvMsg(any) error            { return nil }

func (s *gracefulReportStateStream) record(events ...string) {
	s.mu.Lock()
	s.events = append(s.events, events...)
	s.mu.Unlock()
}

func TestReportStateSendClose_GracefulClosePrecedesStreamCancellation(t *testing.T) {
	// Given
	reportSession := newReportStateSession(context.Background())
	stream := &gracefulReportStateStream{ctx: reportSession.streamContext}
	reportSession.bind(stream)
	if err := reportSession.Send(&pb.State{}); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}

	// When
	result := reportSession.shutdown(context.Background(), context.Canceled)

	// Then
	if result.Err != nil || result.Forced {
		t.Fatalf("graceful shutdown result = %+v, want success", result)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	assertStreamEvents(t, stream.events, []string{"send:start", "send:end", "close:start", "close:end"})
	if !stream.contextLiveAtClose || stream.closeCount != 1 {
		t.Fatalf("graceful close: liveAtClose=%t closeCount=%d", stream.contextLiveAtClose, stream.closeCount)
	}
	if reportSession.streamContext.Err() != nil {
		t.Fatalf("graceful stream context = %v, want live for peer trailers", reportSession.streamContext.Err())
	}
}

func TestReportStateSendClose_NoActiveSendClosesGracefully(t *testing.T) {
	// Given
	reportSession := newReportStateSession(context.Background())
	stream := &gracefulReportStateStream{ctx: reportSession.streamContext}
	reportSession.bind(stream)

	// When
	result := reportSession.shutdown(context.Background(), context.Canceled)

	// Then
	if result.Err != nil || result.Forced {
		t.Fatalf("no-active shutdown result = %+v, want graceful success", result)
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	assertStreamEvents(t, stream.events, []string{"close:start", "close:end"})
	if !stream.contextLiveAtClose || stream.closeCount != 1 {
		t.Fatalf("no-active close: liveAtClose=%t closeCount=%d", stream.contextLiveAtClose, stream.closeCount)
	}
	if reportSession.streamContext.Err() != nil {
		t.Fatalf("no-active stream context = %v, want live for peer trailers", reportSession.streamContext.Err())
	}
}
