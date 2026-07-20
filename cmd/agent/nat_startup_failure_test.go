package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestNATShutdown_DialFailureClosesAttachedStreamOnce(t *testing.T) {
	// Given
	dialErr := errors.New("dial failed")
	stream := &natTestStream{}
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(),
		stream: stream,
		dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, dialErr
		},
		keepaliveInterval: time.Hour,
	})

	// When
	awaitStreamSignal(t, done, "NAT dial-failure shutdown")

	// Then
	frames, maxInFlight, closeCount, recvCount := stream.observation()
	wantAttach := []byte{0xff, 0x05, 0xff, 0x05, 'n', 'a', 't', '-', 't', 'e', 's', 't'}
	if len(frames) != 1 || !bytes.Equal(frames[0], wantAttach) {
		t.Fatalf("NAT dial-failure attach changed: frames=%x want=%x", frames, wantAttach)
	}
	if maxInFlight != 1 || closeCount != 1 || recvCount != 0 || stream.ctx.Err() != context.Canceled {
		t.Fatalf("dial failure cleanup: max=%d close=%d recv=%d stream_err=%v", maxInFlight, closeCount, recvCount, stream.ctx.Err())
	}
}

func TestNATSendFailure_AttachFailureClosesOnceWithoutDial(t *testing.T) {
	// Given
	attachErr := errors.New("attach failed")
	dialed := false
	stream := &natTestStream{sendHook: func([]byte) error { return attachErr }}
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(),
		stream: stream,
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
		keepaliveInterval: time.Hour,
	})

	// When
	awaitStreamSignal(t, done, "NAT attach Send-failure shutdown")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if dialed || maxInFlight != 1 || closeCount != 1 || recvCount != 0 {
		t.Fatalf("attach failure cleanup: dialed=%t max=%d close=%d recv=%d", dialed, maxInFlight, closeCount, recvCount)
	}
	if !errors.Is(context.Cause(stream.ctx), attachErr) {
		t.Fatalf("attach failure cancel cause = %v, want %v", context.Cause(stream.ctx), attachErr)
	}
}

func TestNATShutdown_DisableNatDoesNotOpenStreamOrDial(t *testing.T) {
	// Given
	opened := false
	dialed := false
	handler := natHandler{
		openStream: func(context.Context) (pb.NezhaService_IOStreamClient, error) {
			opened = true
			return nil, errors.New("unexpected open")
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("unexpected dial")
		},
	}

	// When
	handler.run(context.Background(), taskFeatureGates{disableNat: true}, &pb.Task{})

	// Then
	if opened || dialed {
		t.Fatalf("DisableNat gate bypassed: opened=%t dialed=%t", opened, dialed)
	}
}
