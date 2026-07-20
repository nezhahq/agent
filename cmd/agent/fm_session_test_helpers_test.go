package main

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/fm"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

type fmTestStream struct {
	pb.NezhaService_IOStreamClient
	ctx context.Context

	sendHook  func([]byte) error
	recvHook  func(int) (*pb.IOStreamData, error)
	closeHook func() error

	mu               sync.Mutex
	frames           [][]byte
	writeInFlight    int
	maxWriteInFlight int
	closeCount       int
	recvCount        int
	closed           bool
	sendAfterClose   int
}

func (s *fmTestStream) Send(message *pb.IOStreamData) error {
	data := append([]byte(nil), message.GetData()...)
	s.mu.Lock()
	if s.closed {
		s.sendAfterClose++
	}
	s.writeInFlight++
	if s.writeInFlight > s.maxWriteInFlight {
		s.maxWriteInFlight = s.writeInFlight
	}
	s.frames = append(s.frames, data)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.writeInFlight--
		s.mu.Unlock()
	}()
	if s.sendHook == nil {
		return nil
	}
	return s.sendHook(data)
}

func (s *fmTestStream) Recv() (*pb.IOStreamData, error) {
	s.mu.Lock()
	s.recvCount++
	call := s.recvCount
	s.mu.Unlock()
	if s.recvHook == nil {
		return nil, io.EOF
	}
	return s.recvHook(call)
}

func (s *fmTestStream) CloseSend() error {
	s.mu.Lock()
	s.writeInFlight++
	if s.writeInFlight > s.maxWriteInFlight {
		s.maxWriteInFlight = s.writeInFlight
	}
	s.closeCount++
	s.closed = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.writeInFlight--
		s.mu.Unlock()
	}()
	if s.closeHook == nil {
		return nil
	}
	return s.closeHook()
}

func (s *fmTestStream) Header() (metadata.MD, error) { return nil, nil }
func (s *fmTestStream) Trailer() metadata.MD         { return nil }
func (s *fmTestStream) Context() context.Context     { return s.ctx }
func (s *fmTestStream) SendMsg(any) error            { return nil }
func (s *fmTestStream) RecvMsg(any) error            { return nil }

type fmStreamObservation struct {
	frames           [][]byte
	maxWriteInFlight int
	closeCount       int
	recvCount        int
	sendAfterClose   int
}

func (s *fmTestStream) observation() fmStreamObservation {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.frames))
	for index := range s.frames {
		frames[index] = append([]byte(nil), s.frames[index]...)
	}
	return fmStreamObservation{
		frames:           frames,
		maxWriteInFlight: s.maxWriteInFlight,
		closeCount:       s.closeCount,
		recvCount:        s.recvCount,
		sendAfterClose:   s.sendAfterClose,
	}
}

type fmTestRun struct {
	parent            context.Context
	stream            *fmTestStream
	startKeepalive    func(*ioStreamWriteOwner, time.Duration) error
	onTaskCreated     func(*fm.Task)
	keepaliveInterval time.Duration
}

func runFMHandlerForTest(t *testing.T, run fmTestRun) <-chan struct{} {
	t.Helper()
	handler := fmHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			run.stream.ctx = ctx
			return run.stream, nil
		},
		newTask: func(dependencies fm.Dependencies) *fm.Task {
			task := fm.NewFMClient(dependencies)
			if run.onTaskCreated != nil {
				run.onTaskCreated(task)
			}
			return task
		},
		startKeepalive: func(owner *ioStreamWriteOwner, interval time.Duration) error {
			if run.startKeepalive != nil {
				return run.startKeepalive(owner, interval)
			}
			return owner.StartKeepalive(interval)
		},
		keepaliveInterval: run.keepaliveInterval,
		shutdownTimeout:   100 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() {
		handler.run(run.parent, taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"fm-test"}`})
		close(done)
	}()
	return done
}
