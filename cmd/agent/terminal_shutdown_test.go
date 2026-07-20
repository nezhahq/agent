package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestTerminalShutdown_RemoteEOFClosesPTYAndJoinsProducerBeforeReturn(t *testing.T) {
	// Given
	releaseRead := make(chan struct{})
	tty := newTerminalTestPTY()
	tty.readRelease = releaseRead
	stream := &terminalTestStream{recvHook: func() (*pb.IOStreamData, error) { return nil, io.EOF }}
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            context.Background(),
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, tty.closed, "PTY close after remote EOF")

	// When
	select {
	case <-done:
		t.Fatal("Terminal returned before the PTY producer joined")
	default:
	}
	close(releaseRead)
	awaitStreamSignal(t, done, "Terminal remote EOF shutdown")

	// Then
	awaitStreamSignal(t, tty.readDone, "PTY producer completion")
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || stream.ctx.Err() != context.Canceled {
		t.Fatalf("remote EOF cleanup: max=%d close=%d recv=%d stream_err=%v", maxInFlight, closeCount, recvCount, stream.ctx.Err())
	}
	t.Logf("Terminal remote EOF max_in_flight=%d close_send=%d recv=%d producer_joined=true", maxInFlight, closeCount, recvCount)
}

func TestTerminalShutdown_SessionCancellationJoinsBlockedReadAndRecv(t *testing.T) {
	// Given
	parent, cancel := context.WithCancel(context.Background())
	releaseRead := make(chan struct{})
	tty := newTerminalTestPTY()
	tty.readRelease = releaseRead
	stream := &terminalTestStream{}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-stream.ctx.Done()
		return nil, context.Cause(stream.ctx)
	}
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            parent,
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, tty.readEntered, "blocked PTY Read")

	// When
	cancel()
	awaitStreamSignal(t, tty.closed, "PTY close after session cancellation")
	select {
	case <-done:
		t.Fatal("Terminal returned before the canceled PTY producer joined")
	default:
	}
	close(releaseRead)
	awaitStreamSignal(t, done, "Terminal session-cancel shutdown")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("session cancel cleanup: max=%d close=%d recv=%d pty_close=%d", maxInFlight, closeCount, recvCount, tty.closes())
	}
}

func TestTerminalShutdown_CancellationUnblocksBlockedSend(t *testing.T) {
	// Given
	parent, cancel := context.WithCancel(context.Background())
	tty := newTerminalTestPTY()
	tty.reads <- terminalPTYRead{data: []byte("blocked-output")}
	sendEntered := make(chan struct{})
	stream := &terminalTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, []byte("blocked-output")) {
			close(sendEntered)
			<-stream.ctx.Done()
			return context.Cause(stream.ctx)
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-stream.ctx.Done()
		return nil, context.Cause(stream.ctx)
	}
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            parent,
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, sendEntered, "blocked PTY Send")

	// When
	cancel()
	awaitStreamSignal(t, done, "Terminal blocked-Send cancellation")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("blocked Send cleanup: max=%d close=%d recv=%d pty_close=%d", maxInFlight, closeCount, recvCount, tty.closes())
	}
}

func TestTerminalSendFailure_CancelsRecvAndReturnsBoundedly(t *testing.T) {
	// Given
	sendErr := errors.New("terminal send failed")
	tty := newTerminalTestPTY()
	tty.reads <- terminalPTYRead{data: []byte("send-error-output")}
	stream := &terminalTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, []byte("send-error-output")) {
			return sendErr
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-stream.ctx.Done()
		return nil, context.Cause(stream.ctx)
	}

	// When
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            context.Background(),
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, done, "Terminal Send failure shutdown")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if !errors.Is(context.Cause(stream.ctx), sendErr) {
		t.Fatalf("stream cancel cause = %v, want %v", context.Cause(stream.ctx), sendErr)
	}
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("Send failure cleanup: max=%d close=%d recv=%d pty_close=%d", maxInFlight, closeCount, recvCount, tty.closes())
	}
}

func TestTerminalShutdown_RemoteEOFUnblocksProducerSendBeforeCloseSend(t *testing.T) {
	// Given
	tty := newTerminalTestPTY()
	tty.reads <- terminalPTYRead{data: []byte("blocked-after-eof")}
	sendEntered := make(chan struct{})
	stream := &terminalTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, []byte("blocked-after-eof")) {
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

	// When
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            context.Background(),
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, done, "remote EOF with blocked producer Send")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("remote EOF blocked Send: max=%d close=%d recv=%d pty_close=%d", maxInFlight, closeCount, recvCount, tty.closes())
	}
}
