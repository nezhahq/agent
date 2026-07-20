package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/fm"
	pb "github.com/nezhahq/agent/proto"
)

func TestGRPCStreamLifecycle_NATBridgesBytesAndHalfCloses(t *testing.T) {
	// Given
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	remotePayload := []byte{0x00, 0xff, 'g', 'r', 'p', 'c'}
	localPayload := []byte{0xff, 0x00, 't', 'c', 'p'}
	conn := &natScriptedReadConn{Conn: local, payload: localPayload, err: io.EOF}
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, events *grpcTCPIOObservation) error {
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		if err := stream.Send(&pb.IOStreamData{Data: remotePayload}); err != nil {
			return err
		}
		return grpcTCPDrainIOStream(stream, events.frames)
	})
	handler := natHandler{
		openStream:            openGRPCTCPStream(fixture.client),
		dial:                  func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		startKeepalive:        (*ioStreamWriteOwner).StartKeepalive,
		startHalfCloseDrain:   startNATHalfCloseDrain,
		keepaliveInterval:     time.Hour,
		halfCloseDrainTimeout: streamFixtureDeadline,
		shutdownTimeout:       streamFixtureDeadline,
	}
	done := make(chan struct{})
	go func() {
		handler.run(context.Background(), taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"nat-tcp","Host":"unused"}`})
		close(done)
	}()

	// When
	receiveGRPCTCPFrame(t, observation.frames, natAttachFrame("nat-tcp"))
	readRemote := make([]byte, len(remotePayload))
	if _, err := io.ReadFull(peer, readRemote); err != nil {
		t.Fatalf("read NAT remote payload: %v", err)
	}
	// Then
	if !bytes.Equal(readRemote, remotePayload) {
		t.Fatalf("NAT remote payload = %x, want %x", readRemote, remotePayload)
	}
	receiveGRPCTCPFrame(t, observation.frames, localPayload)
	receiveGRPCTCPFrame(t, observation.frames, []byte("EOF"))
	requireGRPCTCPNormalReturn(t, observation.returned)
	awaitStreamSignal(t, done, "NAT tcp completion")
}

func TestGRPCStreamLifecycle_FMListsDirectoryAndJoins(t *testing.T) {
	// Given
	directory := t.TempDir()
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, events *grpcTCPIOObservation) error {
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		if err := stream.Send(&pb.IOStreamData{Data: append([]byte{0}, []byte(directory)...)}); err != nil {
			return err
		}
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		return nil
	})
	var task *fm.Task
	handler := fmHandler{
		openStream: openGRPCTCPStream(fixture.client),
		newTask: func(dependencies fm.Dependencies) *fm.Task {
			task = fm.NewFMClient(dependencies)
			return task
		},
		startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
		keepaliveInterval: time.Hour,
		shutdownTimeout:   streamFixtureDeadline,
	}
	done := make(chan struct{})
	go func() {
		handler.run(context.Background(), taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"fm-tcp"}`})
		close(done)
	}()

	// When
	receiveGRPCTCPFrame(t, observation.frames, fmAttachFrame("fm-tcp"))
	frame := awaitStreamOperationResult(t, observation.frames)

	// Then
	wantFrame := make([]byte, 8+len(directory))
	copy(wantFrame, []byte("NZFN"))
	binary.BigEndian.PutUint32(wantFrame[4:8], uint32(len(directory)))
	copy(wantFrame[8:], directory)
	if !bytes.Equal(frame, wantFrame) {
		t.Fatalf("FM list frame = %x, want %x", frame, wantFrame)
	}
	if task == nil {
		t.Fatal("FM task was not created")
	}
	requireGRPCTCPNormalReturn(t, observation.returned)
	awaitStreamSignal(t, done, "FM tcp completion")
	if filepath.Clean(directory) == "" {
		t.Fatal("FM directory fixture unexpectedly empty")
	}
}

func TestGRPCCancellation_FMPeerErrorEndsBoundedly(t *testing.T) {
	// Given
	peerError := errors.New("peer injected failure")
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, events *grpcTCPIOObservation) error {
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		return peerError
	})
	handler := fmHandler{
		openStream:        openGRPCTCPStream(fixture.client),
		newTask:           fm.NewFMClient,
		startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
		keepaliveInterval: time.Hour,
		shutdownTimeout:   streamFixtureDeadline,
	}
	done := make(chan struct{})
	go func() {
		handler.run(context.Background(), taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"fm-error"}`})
		close(done)
	}()

	// When
	receiveGRPCTCPFrame(t, observation.frames, fmAttachFrame("fm-error"))

	// Then
	if err := awaitStreamOperationResult(t, observation.returned); !errors.Is(err, peerError) {
		t.Fatalf("FM server error = %v, want injected failure", err)
	}
	awaitStreamSignal(t, done, "FM peer error completion")
}

func TestGRPCCancellation_NATParentCancelEndsBoundedly(t *testing.T) {
	// Given
	local, peer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close() })
	started := make(chan struct{}, 1)
	fixture, observation := newGRPCTCPIOFixture(t, func(stream pb.NezhaService_IOStreamServer, events *grpcTCPIOObservation) error {
		if err := grpcTCPReceiveFrame(stream, events.frames); err != nil {
			return err
		}
		started <- struct{}{}
		<-stream.Context().Done()
		return stream.Context().Err()
	})
	parent, cancelParent := context.WithCancel(context.Background())
	handler := natHandler{
		openStream:            openGRPCTCPStream(fixture.client),
		dial:                  func(context.Context, string, string) (net.Conn, error) { return local, nil },
		startKeepalive:        (*ioStreamWriteOwner).StartKeepalive,
		startHalfCloseDrain:   startNATHalfCloseDrain,
		keepaliveInterval:     time.Hour,
		halfCloseDrainTimeout: streamFixtureDeadline,
		shutdownTimeout:       streamFixtureDeadline,
	}
	done := make(chan struct{})
	go func() {
		handler.run(parent, taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"nat-cancel","Host":"unused"}`})
		close(done)
	}()
	receiveGRPCTCPFrame(t, observation.frames, natAttachFrame("nat-cancel"))
	awaitStreamSignal(t, started, "NAT cancel server start")

	// When
	cancelParent()

	// Then
	awaitStreamSignal(t, done, "NAT parent cancellation")
	if err := awaitStreamOperationResult(t, observation.returned); !errors.Is(err, context.Canceled) {
		t.Fatalf("NAT server return = %v, want context.Canceled", err)
	}
}
