package main

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type fsTransferGracefulClient struct {
	pb.NezhaServiceClient
	stream   *fsTransferGracefulStream
	deadline time.Time
}

func (c *fsTransferGracefulClient) IOStream(ctx context.Context, _ ...grpc.CallOption) (pb.NezhaService_IOStreamClient, error) {
	c.stream.ctx = ctx
	c.deadline, _ = ctx.Deadline()
	return c.stream, nil
}

type fsTransferGracefulStream struct {
	pb.NezhaService_IOStreamClient

	ctx context.Context

	mu     sync.Mutex
	events []string
}

func (s *fsTransferGracefulStream) Send(*pb.IOStreamData) error {
	s.record("send")
	return nil
}

func (s *fsTransferGracefulStream) Recv() (*pb.IOStreamData, error) {
	s.record("recv:eof")
	return nil, io.EOF
}

func (s *fsTransferGracefulStream) CloseSend() error {
	s.record("close_send")
	return nil
}

func (s *fsTransferGracefulStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fsTransferGracefulStream) Trailer() metadata.MD         { return nil }
func (s *fsTransferGracefulStream) Context() context.Context     { return s.ctx }
func (s *fsTransferGracefulStream) SendMsg(any) error            { return nil }
func (s *fsTransferGracefulStream) RecvMsg(any) error            { return nil }

func (s *fsTransferGracefulStream) record(event string) {
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
}

func (s *fsTransferGracefulStream) observation() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.events...)
}

func TestFsTransferGracefulClose_PreservesFiveMinuteTimeoutAndCloseDrainCancelOrder(t *testing.T) {
	// Given
	originalClient := client
	stream := &fsTransferGracefulStream{}
	fakeClient := &fsTransferGracefulClient{stream: stream}
	client = fakeClient
	t.Cleanup(func() { client = originalClient })
	task := &pb.Task{Data: `{"stream_id":"graceful-order","op":"invalid","path":"/tmp/x"}`}
	started := time.Now()

	// When
	handleFsTransferTask(task)

	// Then
	remaining := fakeClient.deadline.Sub(started)
	if remaining < mcpFsTransferIOTimeout-time.Second || remaining > mcpFsTransferIOTimeout+time.Second {
		t.Fatalf("fs.transfer timeout = %s, want %s", remaining, mcpFsTransferIOTimeout)
	}
	if err := stream.ctx.Err(); err != context.Canceled {
		t.Fatalf("stream context after graceful drain = %v, want context.Canceled", err)
	}
	assertStreamEvents(t, stream.observation(), []string{"send", "send", "close_send", "recv:eof"})
}
