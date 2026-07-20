package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
)

type natWireClient struct {
	pb.NezhaServiceClient
	stream *natWireStream
}

func (c *natWireClient) IOStream(ctx context.Context, _ ...grpc.CallOption) (pb.NezhaService_IOStreamClient, error) {
	c.stream.ctx = ctx
	return c.stream, nil
}

type natWireStream struct {
	pb.NezhaService_IOStreamClient
	ctx context.Context

	remotePayload []byte
	localPayload  []byte
	localObserved chan struct{}
	observeOnce   sync.Once

	mu     sync.Mutex
	frames [][]byte
}

func (s *natWireStream) Send(message *pb.IOStreamData) error {
	frame := append([]byte(nil), message.GetData()...)
	s.mu.Lock()
	s.frames = append(s.frames, frame)
	s.mu.Unlock()
	if bytes.Equal(frame, s.localPayload) {
		s.observeOnce.Do(func() { close(s.localObserved) })
	}
	return nil
}

func (s *natWireStream) Recv() (*pb.IOStreamData, error) {
	if s.remotePayload != nil {
		payload := s.remotePayload
		s.remotePayload = nil
		return &pb.IOStreamData{Data: payload}, nil
	}
	select {
	case <-s.localObserved:
		return nil, io.EOF
	case <-s.ctx.Done():
		return nil, context.Cause(s.ctx)
	}
}

func (s *natWireStream) CloseSend() error         { return nil }
func (s *natWireStream) Context() context.Context { return s.ctx }
func (s *natWireStream) framesSnapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.frames))
	for index := range s.frames {
		frames[index] = append([]byte(nil), s.frames[index]...)
	}
	return frames
}

func TestNATWire_AttachAndRawPayloadsRemainByteIdentical(t *testing.T) {
	// Given
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	remotePayload := []byte{0x00, 0xff, 0x4e, 0x41, 0x54, 0x0a}
	localPayload := []byte{0xff, 0x00, 0x54, 0x43, 0x50, 0x0d, 0x0a}
	stream := &natWireStream{
		remotePayload: remotePayload,
		localPayload:  localPayload,
		localObserved: make(chan struct{}),
	}
	originalClient := client
	client = &natWireClient{stream: stream}
	t.Cleanup(func() { client = originalClient })
	serverResult := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- nil
			return
		}
		defer conn.Close()
		got := make([]byte, len(remotePayload))
		if _, readErr := io.ReadFull(conn, got); readErr != nil {
			serverResult <- nil
			return
		}
		if _, writeErr := conn.Write(localPayload); writeErr != nil {
			serverResult <- nil
			return
		}
		serverResult <- got
	}()
	task := &pb.Task{Data: `{"StreamID":"nat-wire","Host":"` + listener.Addr().String() + `"}`}

	// When
	handleNATTaskWithConfig(context.Background(), taskFeatureGates{}, task)

	// Then
	if got := <-serverResult; !bytes.Equal(got, remotePayload) {
		t.Fatalf("remote-to-local NAT payload changed: got %x want %x", got, remotePayload)
	}
	frames := stream.framesSnapshot()
	wantAttach := []byte{0xff, 0x05, 0xff, 0x05, 'n', 'a', 't', '-', 'w', 'i', 'r', 'e'}
	if len(frames) < 2 || !bytes.Equal(frames[0], wantAttach) || !bytes.Equal(frames[1], localPayload) {
		t.Fatalf("NAT wire changed: frames=%x attach=%x payload=%x", frames, wantAttach, localPayload)
	}
}
