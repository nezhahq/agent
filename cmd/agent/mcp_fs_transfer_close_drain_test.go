package main

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fsTransferCloseDrainClient struct {
	pb.NezhaServiceClient
	stream *fsTransferCloseDrainStream
}

func (c *fsTransferCloseDrainClient) IOStream(ctx context.Context, _ ...grpc.CallOption) (pb.NezhaService_IOStreamClient, error) {
	c.stream.ctx = ctx
	return c.stream, nil
}

type fsTransferCloseDrainStream struct {
	pb.NezhaService_IOStreamClient
	ctx context.Context

	closeErr error
	recvErr  error

	mu                sync.Mutex
	events            []string
	closeCount        int
	recvCount         int
	contextLiveAtRecv bool
}

func (s *fsTransferCloseDrainStream) Send(*pb.IOStreamData) error {
	s.record("send")
	return nil
}

func (s *fsTransferCloseDrainStream) Recv() (*pb.IOStreamData, error) {
	s.mu.Lock()
	s.recvCount++
	s.contextLiveAtRecv = s.ctx.Err() == nil
	s.events = append(s.events, "recv:terminal")
	s.mu.Unlock()
	return nil, s.recvErr
}

func (s *fsTransferCloseDrainStream) CloseSend() error {
	s.mu.Lock()
	s.closeCount++
	s.events = append(s.events, "close_send")
	s.mu.Unlock()
	return s.closeErr
}

func (s *fsTransferCloseDrainStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fsTransferCloseDrainStream) Trailer() metadata.MD         { return nil }
func (s *fsTransferCloseDrainStream) Context() context.Context     { return s.ctx }
func (s *fsTransferCloseDrainStream) SendMsg(any) error            { return nil }
func (s *fsTransferCloseDrainStream) RecvMsg(any) error            { return nil }

func (s *fsTransferCloseDrainStream) record(event string) {
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
}

func (s *fsTransferCloseDrainStream) observation() ([]string, int, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...), s.closeCount, s.recvCount, s.contextLiveAtRecv
}

func TestFsTransferDrain_CancelsOnlyAfterPeerEOFOrFinalStatus(t *testing.T) {
	tests := []struct {
		name    string
		recvErr error
	}{
		{name: "peer EOF", recvErr: io.EOF},
		{name: "peer reset final status", recvErr: status.Error(codes.Unavailable, "peer reset")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			originalClient := client
			stream := &fsTransferCloseDrainStream{recvErr: test.recvErr}
			client = &fsTransferCloseDrainClient{stream: stream}
			t.Cleanup(func() { client = originalClient })
			task := &pb.Task{Data: `{"stream_id":"drain-order","op":"invalid","path":"/tmp/x"}`}

			// When
			handleFsTransferTaskWithConfig(context.Background(), taskFeatureGates{}, task)

			// Then
			events, closeCount, recvCount, contextLiveAtRecv := stream.observation()
			t.Logf("fs.transfer graceful events=%v context_live_at_recv=%t", events, contextLiveAtRecv)
			assertStreamEvents(t, events, []string{"send", "send", "close_send", "recv:terminal"})
			if closeCount != 1 || recvCount != 1 || !contextLiveAtRecv {
				t.Fatalf("close/drain observation: close=%d recv=%d liveAtRecv=%t", closeCount, recvCount, contextLiveAtRecv)
			}
			if !errors.Is(stream.ctx.Err(), context.Canceled) {
				t.Fatalf("stream context after terminal Recv = %v, want context.Canceled", stream.ctx.Err())
			}
		})
	}
}

func TestFsTransferClose_CloseSendErrorIsTerminalAndSkipsDrain(t *testing.T) {
	// Given
	originalClient := client
	closeErr := errors.New("close send failed")
	stream := &fsTransferCloseDrainStream{closeErr: closeErr, recvErr: io.EOF}
	client = &fsTransferCloseDrainClient{stream: stream}
	t.Cleanup(func() { client = originalClient })
	task := &pb.Task{Data: `{"stream_id":"close-error","op":"invalid","path":"/tmp/x"}`}

	// When
	handleFsTransferTaskWithConfig(context.Background(), taskFeatureGates{}, task)

	// Then
	events, closeCount, recvCount, _ := stream.observation()
	t.Logf("fs.transfer CloseSend-error events=%v context_error=%v", events, stream.ctx.Err())
	assertStreamEvents(t, events, []string{"send", "send", "close_send"})
	if closeCount != 1 || recvCount != 0 {
		t.Fatalf("close error observation: close=%d recv=%d, want close=1 recv=0", closeCount, recvCount)
	}
	if !errors.Is(stream.ctx.Err(), context.Canceled) {
		t.Fatalf("stream context after CloseSend error = %v, want context.Canceled", stream.ctx.Err())
	}
}
