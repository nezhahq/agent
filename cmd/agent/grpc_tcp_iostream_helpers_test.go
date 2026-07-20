package main

import (
	"bytes"
	"context"
	"io"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

type grpcTCPIOObservation struct {
	frames   chan []byte
	returned chan error
}

func newGRPCTCPIOFixture(
	t *testing.T,
	run func(pb.NezhaService_IOStreamServer, *grpcTCPIOObservation) error,
) (*grpcTCPFixture, *grpcTCPIOObservation) {
	t.Helper()
	observation := &grpcTCPIOObservation{
		frames:   make(chan []byte, 16),
		returned: make(chan error, 1),
	}
	service := &grpcTCPService{
		requestTask:       func(pb.NezhaService_RequestTaskServer) error { return nil },
		reportSystemState: func(pb.NezhaService_ReportSystemStateServer) error { return nil },
		ioStream: func(stream pb.NezhaService_IOStreamServer) error {
			err := run(stream, observation)
			observation.returned <- err
			return err
		},
	}
	return newGRPCTCPFixture(t, service), observation
}

func receiveGRPCTCPFrame(t *testing.T, frames <-chan []byte, want []byte) {
	t.Helper()
	got := awaitStreamOperationResult(t, frames)
	if !bytes.Equal(got, want) {
		t.Fatalf("grpc frame = %x, want %x", got, want)
	}
}

func openGRPCTCPStream(client pb.NezhaServiceClient) func(context.Context) (pb.NezhaService_IOStreamClient, error) {
	return func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
		return client.IOStream(ctx)
	}
}

func grpcTCPReceiveFrame(stream pb.NezhaService_IOStreamServer, frames chan<- []byte) error {
	message, err := stream.Recv()
	if err != nil {
		return err
	}
	frames <- append([]byte(nil), message.GetData()...)
	return nil
}

func requireGRPCTCPNormalReturn(t *testing.T, returned <-chan error) {
	t.Helper()
	if err := awaitStreamOperationResult(t, returned); err != nil && err != io.EOF {
		t.Fatalf("grpc server handler returned %v, want normal", err)
	}
}
