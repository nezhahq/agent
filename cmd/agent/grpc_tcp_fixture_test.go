package main

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type grpcTCPService struct {
	pb.UnimplementedNezhaServiceServer
	requestTask       func(pb.NezhaService_RequestTaskServer) error
	reportSystemState func(pb.NezhaService_ReportSystemStateServer) error
	ioStream          func(pb.NezhaService_IOStreamServer) error
}

func (s *grpcTCPService) RequestTask(stream pb.NezhaService_RequestTaskServer) error {
	return s.requestTask(stream)
}

func (s *grpcTCPService) ReportSystemState(stream pb.NezhaService_ReportSystemStateServer) error {
	return s.reportSystemState(stream)
}

func (s *grpcTCPService) IOStream(stream pb.NezhaService_IOStreamServer) error {
	return s.ioStream(stream)
}

type grpcTCPFixture struct {
	client pb.NezhaServiceClient
}

func newGRPCTCPFixture(t *testing.T, service *grpcTCPService) *grpcTCPFixture {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen grpc tcp: %v", err)
	}
	server := grpc.NewServer()
	pb.RegisterNezhaServiceServer(server, service)
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()

	dialContext, cancelDial := context.WithTimeout(context.Background(), streamFixtureDeadline)
	defer cancelDial()
	connection, err := grpc.DialContext(
		dialContext,
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		server.Stop()
		_ = listener.Close()
		t.Fatalf("dial grpc tcp: %v", err)
	}

	t.Cleanup(func() {
		if err := connection.Close(); err != nil {
			t.Errorf("close grpc tcp client: %v", err)
		}
		server.Stop()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close grpc tcp listener: %v", err)
		}
		serveErr := awaitStreamOperationResult(t, serveResult)
		if serveErr != nil && !errors.Is(serveErr, grpc.ErrServerStopped) {
			t.Errorf("serve grpc tcp: %v", serveErr)
		}
	})

	return &grpcTCPFixture{client: pb.NewNezhaServiceClient(connection)}
}

func grpcTCPDrainIOStream(stream pb.NezhaService_IOStreamServer, frames chan<- []byte) error {
	for {
		message, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		frames <- append([]byte(nil), message.GetData()...)
	}
}
