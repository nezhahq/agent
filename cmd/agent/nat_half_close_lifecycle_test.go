package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestNATShutdown_LocalEOFHalfCloseKeepsRemoteWritesAlive(t *testing.T) {
	local, peer := net.Pipe()
	conn := newNATObservedConn(&natScriptedReadConn{Conn: local, err: io.EOF})
	t.Cleanup(func() { _ = peer.Close() })
	remotePayload := []byte{0xff, 0x00, 'r', 'e', 's', 'p'}
	releaseRemote := make(chan struct{})
	closeObserved := make(chan struct{})
	recvCalls := 0
	stream := &natTestStream{}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		recvCalls++
		if recvCalls == 1 {
			<-releaseRemote
			return &pb.IOStreamData{Data: remotePayload}, nil
		}
		return nil, io.EOF
	}
	stream.closeHook = func() error { close(closeObserved); return nil }
	done := runNATHandlerForTest(t, natTestRun{parent: context.Background(), stream: stream, dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, closeObserved, "NAT local EOF CloseSend")
	if conn.closes() != 0 {
		t.Fatalf("local EOF closed TCP before remote termination: closes=%d", conn.closes())
	}
	readDone := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, len(remotePayload))
		_, err := io.ReadFull(peer, buffer)
		if err != nil {
			readDone <- nil
			return
		}
		readDone <- buffer
	}()
	close(releaseRemote)
	if got := <-readDone; !bytes.Equal(got, remotePayload) {
		t.Fatalf("remote payload after local EOF=%x want=%x", got, remotePayload)
	}
	awaitStreamSignal(t, done, "NAT final remote EOF after local half-close")
	_, _, closeCount, _ := stream.observation()
	if closeCount != 1 || conn.closes() != 1 {
		t.Fatalf("half-close final cleanup: close_send=%d conn_close=%d", closeCount, conn.closes())
	}
}

func TestNATStreamOwnership_LocalEOFStopsKeepaliveWhileRecvDrains(t *testing.T) {
	local, peer := net.Pipe()
	conn := newNATObservedConn(&natScriptedReadConn{Conn: local, err: io.EOF})
	t.Cleanup(func() { _ = peer.Close() })
	closeObserved := make(chan struct{})
	releaseRemote := make(chan struct{})
	var owner *ioStreamWriteOwner
	stream := &natTestStream{recvHook: func() (*pb.IOStreamData, error) { <-releaseRemote; return nil, io.EOF }, closeHook: func() error { close(closeObserved); return nil }}
	done := runNATHandlerForTest(t, natTestRun{parent: context.Background(), stream: stream, dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, startKeepalive: func(writeOwner *ioStreamWriteOwner, interval time.Duration) error {
		owner = writeOwner
		return writeOwner.StartKeepalive(interval)
	}, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, closeObserved, "NAT half-close after keepalive stop")
	framesBeforeTick, _, _, _ := stream.observation()
	if err := owner.Send(&pb.IOStreamData{Data: []byte{}}); !errors.Is(err, errIOStreamWriteClosed) {
		t.Fatalf("post-half-close keepalive tick error=%v want write closed", err)
	}
	framesAfterTick, _, _, _ := stream.observation()
	if len(framesAfterTick) != len(framesBeforeTick) {
		t.Fatalf("keepalive tick reached stream after half-close: before=%q after=%q", framesBeforeTick, framesAfterTick)
	}
	close(releaseRemote)
	awaitStreamSignal(t, done, "NAT remote EOF after keepalive stopped")
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("keepalive half-close cleanup: max=%d close=%d recv=%d conn_close=%d", maxInFlight, closeCount, recvCount, conn.closes())
	}
}

func TestNATShutdown_HalfCloseDrainTimeoutClosesAndJoins(t *testing.T) {
	local, peer := net.Pipe()
	conn := newNATObservedConn(&natScriptedReadConn{Conn: local, err: io.EOF})
	t.Cleanup(func() { _ = peer.Close() })
	drain := make(chan time.Time, 1)
	closeObserved := make(chan struct{})
	stream := &natTestStream{}
	stream.recvHook = func() (*pb.IOStreamData, error) { <-stream.ctx.Done(); return nil, context.Cause(stream.ctx) }
	stream.closeHook = func() error { close(closeObserved); return nil }
	done := runNATHandlerForTest(t, natTestRun{parent: context.Background(), stream: stream, dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, startHalfCloseDrain: func(time.Duration) (<-chan time.Time, func()) { return drain, func() {} }, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, closeObserved, "NAT half-close CloseSend")
	drain <- time.Now()
	awaitStreamSignal(t, done, "NAT half-close drain timeout")
	_, _, closeCount, recvCount := stream.observation()
	if closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("drain timeout cleanup: close_send=%d recv=%d conn_close=%d", closeCount, recvCount, conn.closes())
	}
}
