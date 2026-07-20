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

func TestNATShutdown_RemoteEOFClosesTCPAndJoinsReaderBeforeReturn(t *testing.T) {
	// Given
	local, peer := net.Pipe()
	releaseRead := make(chan struct{})
	conn := newNATObservedConn(local)
	conn.readRelease = releaseRead
	t.Cleanup(func() { _ = peer.Close() })
	stream := &natTestStream{}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-conn.readEntered
		return nil, io.EOF
	}
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(), stream: stream,
		dial:              func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, conn.closed, "TCP close after remote EOF")

	// When
	select {
	case <-done:
		t.Fatal("NAT returned before the TCP reader joined")
	default:
	}
	close(releaseRead)
	awaitStreamSignal(t, done, "NAT remote EOF shutdown")

	// Then
	awaitStreamSignal(t, conn.readDone, "NAT TCP reader completion")
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("remote EOF cleanup: max=%d close=%d recv=%d conn_close=%d", maxInFlight, closeCount, recvCount, conn.closes())
	}
}

func TestNATShutdown_LocalReadErrorHalfClosesThenWaitsForRemoteEOF(t *testing.T) {
	// Given
	local, peer := net.Pipe()
	conn := newNATObservedConn(local)
	errorFrame := make(chan struct{})
	remoteEOF := make(chan struct{})
	closeObserved := make(chan struct{})
	stream := &natTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, []byte(io.EOF.Error())) {
			close(errorFrame)
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-errorFrame
		<-remoteEOF
		return nil, io.EOF
	}
	stream.closeHook = func() error { close(closeObserved); return nil }
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(), stream: stream,
		dial:              func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, conn.readEntered, "NAT TCP Read before local EOF")

	// When
	if err := peer.Close(); err != nil {
		t.Fatalf("close NAT peer: %v", err)
	}
	awaitStreamSignal(t, closeObserved, "NAT local read-error CloseSend")
	if conn.closes() != 0 {
		t.Fatalf("local read error closed TCP before remote EOF: closes=%d", conn.closes())
	}
	close(remoteEOF)
	awaitStreamSignal(t, done, "NAT remote EOF after local read error")

	// Then
	frames, maxInFlight, closeCount, recvCount := stream.observation()
	if len(frames) != 2 || !bytes.Equal(frames[1], []byte(io.EOF.Error())) {
		t.Fatalf("NAT local read error frame changed: frames=%q", frames)
	}
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("local read cleanup: max=%d close=%d recv=%d conn_close=%d", maxInFlight, closeCount, recvCount, conn.closes())
	}
}

func TestNATSendFailure_ClosesTCPJoinsReaderAndCancelsRecv(t *testing.T) {
	// Given
	local, peer := net.Pipe()
	conn := newNATObservedConn(local)
	t.Cleanup(func() { _ = peer.Close() })
	payload := []byte("send-failure")
	sendErr := errors.New("NAT send failed")
	stream := &natTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, payload) {
			return sendErr
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-stream.ctx.Done()
		return nil, context.Cause(stream.ctx)
	}
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(), stream: stream,
		dial:              func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		keepaliveInterval: time.Hour,
	})
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(payload)
		writeDone <- err
	}()

	// When
	awaitStreamSignal(t, done, "NAT owner Send failure shutdown")

	// Then
	if err := <-writeDone; err != nil {
		t.Fatalf("write NAT Send-failure payload: %v", err)
	}
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if !errors.Is(context.Cause(stream.ctx), sendErr) {
		t.Fatalf("stream cancel cause = %v, want %v", context.Cause(stream.ctx), sendErr)
	}
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("Send failure cleanup: max=%d close=%d recv=%d conn_close=%d", maxInFlight, closeCount, recvCount, conn.closes())
	}
}

func TestNATShutdown_SessionCancellationJoinsBlockedReadAndRecv(t *testing.T) {
	// Given
	parent, cancel := context.WithCancel(context.Background())
	local, peer := net.Pipe()
	releaseRead := make(chan struct{})
	conn := newNATObservedConn(local)
	conn.readRelease = releaseRead
	t.Cleanup(func() { _ = peer.Close() })
	stream := &natTestStream{}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-stream.ctx.Done()
		return nil, context.Cause(stream.ctx)
	}
	done := runNATHandlerForTest(t, natTestRun{
		parent: parent, stream: stream,
		dial:              func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, conn.readEntered, "blocked NAT TCP Read")

	// When
	cancel()
	awaitStreamSignal(t, conn.closed, "TCP close after NAT session cancellation")
	select {
	case <-done:
		t.Fatal("NAT returned before the canceled TCP reader joined")
	default:
	}
	close(releaseRead)
	awaitStreamSignal(t, done, "NAT session-cancel shutdown")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("session cancel cleanup: max=%d close=%d recv=%d conn_close=%d", maxInFlight, closeCount, recvCount, conn.closes())
	}
}

func TestNATShutdown_RemoteEOFUnblocksBlockedReaderSendBeforeCloseSend(t *testing.T) {
	// Given
	local, peer := net.Pipe()
	conn := newNATObservedConn(local)
	t.Cleanup(func() { _ = peer.Close() })
	payload := []byte("blocked-after-eof")
	sendEntered := make(chan struct{})
	stream := &natTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, payload) {
			close(sendEntered)
			<-stream.ctx.Done()
			return context.Cause(stream.ctx)
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-sendEntered
		return nil, io.EOF
	}
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(), stream: stream,
		dial:              func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		keepaliveInterval: time.Hour,
	})
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(payload)
		writeDone <- err
	}()

	// When
	awaitStreamSignal(t, done, "NAT remote EOF with blocked reader Send")

	// Then
	if err := <-writeDone; err != nil {
		t.Fatalf("write blocked NAT payload: %v", err)
	}
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("remote EOF blocked Send: max=%d close=%d recv=%d conn_close=%d", maxInFlight, closeCount, recvCount, conn.closes())
	}
}

func TestNATShutdown_SessionCancellationUnblocksBlockedLocalWrite(t *testing.T) {
	// Given
	parent, cancel := context.WithCancel(context.Background())
	local, peer := net.Pipe()
	conn := newNATObservedConn(local)
	t.Cleanup(func() { _ = peer.Close() })
	stream := &natTestStream{}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		return &pb.IOStreamData{Data: []byte("blocked-local-write")}, nil
	}
	done := runNATHandlerForTest(t, natTestRun{
		parent: parent, stream: stream,
		dial:              func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, conn.writeEntered, "blocked NAT local Write")

	// When
	cancel()
	awaitStreamSignal(t, done, "NAT cancellation with blocked local Write")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("blocked local Write cleanup: max=%d close=%d recv=%d conn_close=%d", maxInFlight, closeCount, recvCount, conn.closes())
	}
}
