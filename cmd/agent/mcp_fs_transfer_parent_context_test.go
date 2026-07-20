package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type parentCanceledFsTransferClient struct {
	pb.NezhaServiceClient
	stream  *parentCanceledFsTransferStream
	context context.Context
}

func (c *parentCanceledFsTransferClient) IOStream(ctx context.Context, _ ...grpc.CallOption) (pb.NezhaService_IOStreamClient, error) {
	c.context = ctx
	c.stream.ctx = ctx
	return c.stream, nil
}

type parentCanceledFsTransferStream struct {
	pb.NezhaService_IOStreamClient
	ctx context.Context

	sendStarted chan struct{}
	startOnce   sync.Once
	mu          sync.Mutex
	closeCount  int
	recvCount   int
	liveAtClose bool
}

func (s *parentCanceledFsTransferStream) Send(*pb.IOStreamData) error {
	s.startOnce.Do(func() { close(s.sendStarted) })
	<-s.ctx.Done()
	return context.Cause(s.ctx)
}

func (s *parentCanceledFsTransferStream) Recv() (*pb.IOStreamData, error) {
	s.mu.Lock()
	s.recvCount++
	s.mu.Unlock()
	return nil, errors.New("Recv must not run after forced parent cancellation")
}

func (s *parentCanceledFsTransferStream) CloseSend() error {
	s.mu.Lock()
	s.closeCount++
	s.liveAtClose = s.ctx.Err() == nil
	s.mu.Unlock()
	return context.Cause(s.ctx)
}

func (s *parentCanceledFsTransferStream) Header() (metadata.MD, error) { return nil, nil }
func (s *parentCanceledFsTransferStream) Trailer() metadata.MD         { return nil }
func (s *parentCanceledFsTransferStream) Context() context.Context     { return s.ctx }
func (s *parentCanceledFsTransferStream) SendMsg(any) error            { return nil }
func (s *parentCanceledFsTransferStream) RecvMsg(any) error            { return nil }

func (s *parentCanceledFsTransferStream) observation() (int, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeCount, s.recvCount, s.liveAtClose
}

func TestFsTransferClose_ParentCancellationStopsTransferAndClosesOnce(t *testing.T) {
	// Given
	originalClient := client
	restoreRuntimeConfigSnapshot(t)
	publishRuntimeConfig(model.AgentConfig{})
	stream := &parentCanceledFsTransferStream{sendStarted: make(chan struct{})}
	fakeClient := &parentCanceledFsTransferClient{stream: stream}
	client = fakeClient
	t.Cleanup(func() { client = originalClient })
	parent, cancelParent := context.WithCancel(context.Background())
	task := &pb.Task{Data: `{"stream_id":"parent-cancel","op":"invalid","path":"/tmp/x"}`}
	handlerExited := make(chan struct{})
	go func() {
		doTaskWithContext(parent, &pb.Task{Type: model.TaskTypeFsTransfer, Data: task.GetData()})
		close(handlerExited)
	}()
	awaitStreamSignal(t, stream.sendStarted, "fs.transfer attach Send entry")

	// When
	cancelParent()
	awaitStreamSignal(t, handlerExited, "fs.transfer parent cancellation")

	// Then
	if !errors.Is(fakeClient.context.Err(), context.Canceled) {
		t.Fatalf("IOStream context error = %v, want context.Canceled", fakeClient.context.Err())
	}
	closeCount, recvCount, liveAtClose := stream.observation()
	if closeCount != 1 || recvCount != 0 || liveAtClose {
		t.Fatalf("forced parent-cancel observation: close=%d recv=%d liveAtClose=%t, want close=1 recv=0 liveAtClose=false", closeCount, recvCount, liveAtClose)
	}
	t.Logf("fs.transfer parent-cancel context_error=%v close_count=%d recv_count=%d live_at_close=%t", fakeClient.context.Err(), closeCount, recvCount, liveAtClose)
}
