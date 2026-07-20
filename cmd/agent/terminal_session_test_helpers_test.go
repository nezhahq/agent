package main

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

type terminalPTYRead struct {
	data []byte
	err  error
}

type terminalTestPTY struct {
	reads chan terminalPTYRead

	readEntered  chan struct{}
	readRelease  <-chan struct{}
	closed       chan struct{}
	closeOnce    sync.Once
	readDone     chan struct{}
	readDoneOnce sync.Once
	closeErr     error

	mu         sync.Mutex
	closeCount int
	writes     [][]byte
	sizes      []terminalWindowSize
}

func newTerminalTestPTY() *terminalTestPTY {
	return &terminalTestPTY{
		reads:       make(chan terminalPTYRead, 4),
		readEntered: make(chan struct{}, 4),
		closed:      make(chan struct{}),
		readDone:    make(chan struct{}),
	}
}

func (p *terminalTestPTY) Read(buffer []byte) (int, error) {
	p.readEntered <- struct{}{}
	var result terminalPTYRead
	select {
	case result = <-p.reads:
	case <-p.closed:
		result.err = io.ErrClosedPipe
	}
	if p.readRelease != nil {
		<-p.readRelease
	}
	p.readDoneOnce.Do(func() { close(p.readDone) })
	return copy(buffer, result.data), result.err
}

func (p *terminalTestPTY) Write(data []byte) (int, error) {
	p.mu.Lock()
	p.writes = append(p.writes, append([]byte(nil), data...))
	p.mu.Unlock()
	return len(data), nil
}

func (p *terminalTestPTY) Getsize() (uint16, uint16, error) { return 80, 24, nil }

func (p *terminalTestPTY) Setsize(cols, rows uint32) error {
	p.mu.Lock()
	p.sizes = append(p.sizes, terminalWindowSize{Cols: cols, Rows: rows})
	p.mu.Unlock()
	return nil
}

func (p *terminalTestPTY) Close() error {
	p.mu.Lock()
	p.closeCount++
	p.mu.Unlock()
	p.closeOnce.Do(func() { close(p.closed) })
	return p.closeErr
}

func (p *terminalTestPTY) closes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeCount
}

var _ pty.IPty = (*terminalTestPTY)(nil)

type terminalTestStream struct {
	pb.NezhaService_IOStreamClient
	ctx context.Context

	sendHook  func([]byte) error
	recvHook  func() (*pb.IOStreamData, error)
	closeHook func() error

	mu               sync.Mutex
	frames           [][]byte
	writeInFlight    int
	maxWriteInFlight int
	closeCount       int
	recvCount        int
}

func (s *terminalTestStream) Send(message *pb.IOStreamData) error {
	data := append([]byte(nil), message.GetData()...)
	s.beginWrite()
	defer s.endWrite()
	s.mu.Lock()
	s.frames = append(s.frames, data)
	s.mu.Unlock()
	if s.sendHook == nil {
		return nil
	}
	return s.sendHook(data)
}

func (s *terminalTestStream) Recv() (*pb.IOStreamData, error) {
	s.mu.Lock()
	s.recvCount++
	s.mu.Unlock()
	if s.recvHook == nil {
		return nil, io.EOF
	}
	return s.recvHook()
}

func (s *terminalTestStream) CloseSend() error {
	s.beginWrite()
	defer s.endWrite()
	s.mu.Lock()
	s.closeCount++
	s.mu.Unlock()
	if s.closeHook == nil {
		return nil
	}
	return s.closeHook()
}

func (s *terminalTestStream) Header() (metadata.MD, error) { return nil, nil }
func (s *terminalTestStream) Trailer() metadata.MD         { return nil }
func (s *terminalTestStream) Context() context.Context     { return s.ctx }
func (s *terminalTestStream) SendMsg(any) error            { return nil }
func (s *terminalTestStream) RecvMsg(any) error            { return nil }

func (s *terminalTestStream) beginWrite() {
	s.mu.Lock()
	s.writeInFlight++
	if s.writeInFlight > s.maxWriteInFlight {
		s.maxWriteInFlight = s.writeInFlight
	}
	s.mu.Unlock()
}

func (s *terminalTestStream) endWrite() {
	s.mu.Lock()
	s.writeInFlight--
	s.mu.Unlock()
}

func (s *terminalTestStream) observation() ([][]byte, int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.frames))
	for i := range s.frames {
		frames[i] = append([]byte(nil), s.frames[i]...)
	}
	return frames, s.maxWriteInFlight, s.closeCount, s.recvCount
}

type terminalTestRun struct {
	parent            context.Context
	stream            *terminalTestStream
	tty               *terminalTestPTY
	keepaliveInterval time.Duration
	startKeepalive    func(*ioStreamWriteOwner, time.Duration) error
}

func runTerminalHandlerForTest(t *testing.T, run terminalTestRun) <-chan struct{} {
	t.Helper()
	handler := terminalHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			run.stream.ctx = ctx
			return run.stream, nil
		},
		startPTY: func() (pty.IPty, error) { return run.tty, nil },
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
		handler.run(run.parent, taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"terminal-test"}`})
		close(done)
	}()
	return done
}
