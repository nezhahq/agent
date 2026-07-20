package main

import (
	"context"
	"errors"
	"net"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufconnFixtureSize = 1024 * 1024

type bufconnServerStream[Res any] interface {
	Context() context.Context
	Send(*Res) error
}

type bufconnStreamController[Res any] struct {
	started  chan struct{}
	release  chan *Res
	canceled chan error
}

func newBufconnStreamController[Res any]() *bufconnStreamController[Res] {
	return &bufconnStreamController[Res]{
		started:  make(chan struct{}, 1),
		release:  make(chan *Res, 1),
		canceled: make(chan error, 1),
	}
}

func (c *bufconnStreamController[Res]) serve(stream bufconnServerStream[Res]) error {
	c.started <- struct{}{}
	select {
	case message := <-c.release:
		return stream.Send(message)
	case <-stream.Context().Done():
		err := stream.Context().Err()
		c.canceled <- err
		return err
	}
}

type bufconnNezhaService struct {
	pb.UnimplementedNezhaServiceServer
	requestTask       *bufconnStreamController[pb.Task]
	reportSystemState *bufconnStreamController[pb.Receipt]
	ioStream          *bufconnStreamController[pb.IOStreamData]
}

func (s *bufconnNezhaService) RequestTask(stream pb.NezhaService_RequestTaskServer) error {
	return s.requestTask.serve(stream)
}

func (s *bufconnNezhaService) ReportSystemState(stream pb.NezhaService_ReportSystemStateServer) error {
	return s.reportSystemState.serve(stream)
}

func (s *bufconnNezhaService) IOStream(stream pb.NezhaService_IOStreamServer) error {
	return s.ioStream.serve(stream)
}

type bufconnFixture struct {
	client            pb.NezhaServiceClient
	requestTask       *bufconnStreamController[pb.Task]
	reportSystemState *bufconnStreamController[pb.Receipt]
	ioStream          *bufconnStreamController[pb.IOStreamData]
}

func newBufconnFixture(t *testing.T) *bufconnFixture {
	t.Helper()
	listener := bufconn.Listen(bufconnFixtureSize)
	service := &bufconnNezhaService{
		requestTask:       newBufconnStreamController[pb.Task](),
		reportSystemState: newBufconnStreamController[pb.Receipt](),
		ioStream:          newBufconnStreamController[pb.IOStreamData](),
	}
	server := grpc.NewServer()
	pb.RegisterNezhaServiceServer(server, service)
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()

	dialContext, cancelDial := context.WithTimeout(context.Background(), streamFixtureDeadline)
	defer cancelDial()
	connection, err := grpc.DialContext(
		dialContext,
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		server.Stop()
		t.Fatalf("dial bufconn: %v", err)
	}

	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close bufconn client: %v", err)
		}
		server.Stop()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close bufconn listener: %v", err)
		}
		serveErr := awaitStreamOperationResult(t, serveResult)
		if serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			t.Errorf("serve bufconn: %v", serveErr)
		}
	})

	return &bufconnFixture{
		client:            pb.NewNezhaServiceClient(connection),
		requestTask:       service.requestTask,
		reportSystemState: service.reportSystemState,
		ioStream:          service.ioStream,
	}
}

func (f *bufconnFixture) waitRequestTaskStarted(t *testing.T) {
	t.Helper()
	awaitStreamSignal(t, f.requestTask.started, "bufconn RequestTask start")
}

func (f *bufconnFixture) releaseRequestTask(message *pb.Task) { f.requestTask.release <- message }

func (f *bufconnFixture) waitRequestTaskCanceled(t *testing.T) error {
	t.Helper()
	return awaitStreamOperationResult(t, f.requestTask.canceled)
}

func (f *bufconnFixture) waitReportSystemStateStarted(t *testing.T) {
	t.Helper()
	awaitStreamSignal(t, f.reportSystemState.started, "bufconn ReportSystemState start")
}

func (f *bufconnFixture) releaseReportSystemState(message *pb.Receipt) {
	f.reportSystemState.release <- message
}

func (f *bufconnFixture) waitReportSystemStateCanceled(t *testing.T) error {
	t.Helper()
	return awaitStreamOperationResult(t, f.reportSystemState.canceled)
}

func (f *bufconnFixture) waitIOStreamStarted(t *testing.T) {
	t.Helper()
	awaitStreamSignal(t, f.ioStream.started, "bufconn IOStream start")
}

func (f *bufconnFixture) releaseIOStream(message *pb.IOStreamData) { f.ioStream.release <- message }

func (f *bufconnFixture) waitIOStreamCanceled(t *testing.T) error {
	t.Helper()
	return awaitStreamOperationResult(t, f.ioStream.canceled)
}
