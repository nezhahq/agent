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

type natPartialWriteConn struct {
	net.Conn
	writeErr error
	writes   int
}

func (c *natPartialWriteConn) Write(data []byte) (int, error) {
	c.writes++
	if c.writes == 1 {
		return len(data) / 2, nil
	}
	return 0, c.writeErr
}

func TestNATSendFailure_TailFailureSkipsLegacyErrorFrame(t *testing.T) {
	local, peer := net.Pipe()
	payload := []byte("tail-send-fails")
	conn := newNATObservedConn(&natScriptedReadConn{Conn: local, payload: payload, err: io.EOF})
	t.Cleanup(func() { _ = peer.Close() })
	sendErr := errors.New("tail send failed")
	stream := &natTestStream{sendHook: func(data []byte) error {
		if bytes.Equal(data, payload) {
			return sendErr
		}
		return nil
	}}
	stream.recvHook = func() (*pb.IOStreamData, error) { <-stream.ctx.Done(); return nil, context.Cause(stream.ctx) }
	done := runNATHandlerForTest(t, natTestRun{parent: context.Background(), stream: stream, dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, done, "NAT tail Send failure")
	frames, _, closeCount, _ := stream.observation()
	if len(frames) != 2 || !bytes.Equal(frames[1], payload) {
		t.Fatalf("tail Send failure emitted extra frame: %q", frames)
	}
	if closeCount != 1 || conn.closes() != 1 {
		t.Fatalf("tail Send cleanup: close_send=%d conn_close=%d", closeCount, conn.closes())
	}
}

func TestNATSendFailure_LegacyErrorFailureDoesNotRetryFrame(t *testing.T) {
	local, peer := net.Pipe()
	readErr := errors.New("legacy error send fails")
	conn := newNATObservedConn(&natScriptedReadConn{Conn: local, payload: []byte("tail"), err: readErr})
	t.Cleanup(func() { _ = peer.Close() })
	sendErr := errors.New("error frame send failed")
	stream := &natTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, []byte(readErr.Error())) {
			return sendErr
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) { <-stream.ctx.Done(); return nil, context.Cause(stream.ctx) }
	done := runNATHandlerForTest(t, natTestRun{parent: context.Background(), stream: stream, dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, done, "NAT legacy error Send failure")
	frames, _, closeCount, _ := stream.observation()
	want := [][]byte{{0xff, 0x05, 0xff, 0x05, 'n', 'a', 't', '-', 't', 'e', 's', 't'}, []byte("tail"), []byte(readErr.Error())}
	if len(frames) != len(want) {
		t.Fatalf("legacy error Send retried or added frames: %q", frames)
	}
	for index := range want {
		if !bytes.Equal(frames[index], want[index]) {
			t.Fatalf("legacy error Send frame %d=%q want=%q", index, frames[index], want[index])
		}
	}
	if closeCount != 1 || conn.closes() != 1 {
		t.Fatalf("legacy error Send cleanup: close_send=%d conn_close=%d", closeCount, conn.closes())
	}
}

func TestNATShutdown_RemotePartialWriteErrorFullyCloses(t *testing.T) {
	local, peer := net.Pipe()
	writeErr := errors.New("partial write failed")
	conn := newNATObservedConn(&natPartialWriteConn{Conn: local, writeErr: writeErr})
	t.Cleanup(func() { _ = peer.Close() })
	stream := &natTestStream{recvHook: func() (*pb.IOStreamData, error) { return &pb.IOStreamData{Data: []byte("response")}, nil }}
	done := runNATHandlerForTest(t, natTestRun{parent: context.Background(), stream: stream, dial: func(context.Context, string, string) (net.Conn, error) { return conn, nil }, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, done, "NAT partial local Write failure")
	_, _, closeCount, recvCount := stream.observation()
	if closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("partial Write cleanup: close_send=%d recv=%d conn_close=%d", closeCount, recvCount, conn.closes())
	}
}
