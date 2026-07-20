package main

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

type natObservedConn struct {
	net.Conn
	readEntered  chan struct{}
	writeEntered chan struct{}
	readRelease  <-chan struct{}
	readDone     chan struct{}
	closed       chan struct{}

	readDoneOnce sync.Once
	closeOnce    sync.Once
	mu           sync.Mutex
	closeCount   int
}

func newNATObservedConn(conn net.Conn) *natObservedConn {
	return &natObservedConn{
		Conn:         conn,
		readEntered:  make(chan struct{}, 4),
		writeEntered: make(chan struct{}, 4),
		readDone:     make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *natObservedConn) Write(data []byte) (int, error) {
	c.writeEntered <- struct{}{}
	return c.Conn.Write(data)
}

func (c *natObservedConn) Read(buffer []byte) (int, error) {
	c.readEntered <- struct{}{}
	read, err := c.Conn.Read(buffer)
	if c.readRelease != nil {
		<-c.readRelease
	}
	c.readDoneOnce.Do(func() { close(c.readDone) })
	return read, err
}

func (c *natObservedConn) Close() error {
	c.mu.Lock()
	c.closeCount++
	c.mu.Unlock()
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *natObservedConn) closes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCount
}

type natTestStream struct {
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

func (s *natTestStream) Send(message *pb.IOStreamData) error {
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

func (s *natTestStream) Recv() (*pb.IOStreamData, error) {
	s.mu.Lock()
	s.recvCount++
	s.mu.Unlock()
	if s.recvHook == nil {
		return nil, io.EOF
	}
	return s.recvHook()
}

func (s *natTestStream) CloseSend() error {
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

func (s *natTestStream) Context() context.Context { return s.ctx }

func (s *natTestStream) beginWrite() {
	s.mu.Lock()
	s.writeInFlight++
	if s.writeInFlight > s.maxWriteInFlight {
		s.maxWriteInFlight = s.writeInFlight
	}
	s.mu.Unlock()
}

func (s *natTestStream) endWrite() {
	s.mu.Lock()
	s.writeInFlight--
	s.mu.Unlock()
}

func (s *natTestStream) observation() ([][]byte, int, int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.frames))
	for index := range s.frames {
		frames[index] = append([]byte(nil), s.frames[index]...)
	}
	return frames, s.maxWriteInFlight, s.closeCount, s.recvCount
}

type natTestRun struct {
	parent              context.Context
	stream              *natTestStream
	dial                func(context.Context, string, string) (net.Conn, error)
	startKeepalive      func(*ioStreamWriteOwner, time.Duration) error
	startHalfCloseDrain func(time.Duration) (<-chan time.Time, func())
	keepaliveInterval   time.Duration
}

func runNATHandlerForTest(t *testing.T, run natTestRun) <-chan struct{} {
	t.Helper()
	handler := natHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			run.stream.ctx = ctx
			return run.stream, nil
		},
		dial: run.dial,
		startKeepalive: func(owner *ioStreamWriteOwner, interval time.Duration) error {
			if run.startKeepalive != nil {
				return run.startKeepalive(owner, interval)
			}
			return owner.StartKeepalive(interval)
		},
		startHalfCloseDrain: run.startHalfCloseDrain,
		keepaliveInterval:   run.keepaliveInterval,
		shutdownTimeout:     100 * time.Millisecond,
	}
	done := make(chan struct{})
	go func() {
		handler.run(run.parent, taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"nat-test","Host":"local.test:1"}`})
		close(done)
	}()
	return done
}
