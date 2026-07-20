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

func TestTerminalStreamOwnership_SerializesKeepaliveAndPTYAndClosesOnce(t *testing.T) {
	// Given
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	tty := newTerminalTestPTY()
	tty.reads <- terminalPTYRead{data: []byte("pty-output")}
	ptySendEntered := make(chan struct{})
	keepaliveEntered := make(chan struct{})
	releasePTYSend := make(chan struct{})
	stream := &terminalTestStream{}
	stream.sendHook = func(data []byte) error {
		switch {
		case bytes.Equal(data, []byte("pty-output")):
			close(ptySendEntered)
			<-releasePTYSend
		case len(data) == 0:
			select {
			case <-keepaliveEntered:
			default:
				close(keepaliveEntered)
			}
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-keepaliveEntered
		return nil, io.EOF
	}
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            parent,
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
		startKeepalive: func(owner *ioStreamWriteOwner, _ time.Duration) error {
			go func() {
				<-ptySendEntered
				_ = owner.Send(&pb.IOStreamData{Data: []byte{}})
			}()
			return nil
		},
	})
	awaitStreamSignal(t, ptySendEntered, "PTY Send entry")
	close(releasePTYSend)
	awaitStreamSignal(t, keepaliveEntered, "serialized keepalive Send")

	// When
	awaitStreamSignal(t, done, "Terminal ownership shutdown")
	awaitStreamSignal(t, tty.readDone, "PTY producer completion")

	// Then
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("Terminal ownership: max_in_flight=%d close_send=%d recv=%d pty_close=%d, want 1/1/1/1", maxInFlight, closeCount, recvCount, tty.closes())
	}
	t.Logf("Terminal ownership max_in_flight=%d close_send=%d recv=%d pty_close=%d producer_joined=true", maxInFlight, closeCount, recvCount, tty.closes())
}

func TestTerminalStreamOwnership_PTYReadErrorUsesOwnerWithoutProducerClose(t *testing.T) {
	// Given
	tty := newTerminalTestPTY()
	readErr := errors.New("pty read failed")
	tty.reads <- terminalPTYRead{err: readErr}
	producerFrame := make(chan struct{})
	stream := &terminalTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, []byte(readErr.Error())) {
			close(producerFrame)
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-producerFrame
		return nil, io.EOF
	}

	// When
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            context.Background(),
		stream:            stream,
		tty:               tty,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, done, "PTY read-error shutdown")

	// Then
	frames, maxInFlight, closeCount, recvCount := stream.observation()
	if len(frames) != 2 || !bytes.Equal(frames[1], []byte(readErr.Error())) {
		t.Fatalf("PTY error frame changed: frames=%q", frames)
	}
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("PTY error ownership: max=%d close=%d recv=%d pty_close=%d, want 1/1/1/1", maxInFlight, closeCount, recvCount, tty.closes())
	}
	t.Logf("Terminal PTY error frame=%x max_in_flight=%d close_send=%d producer_joined=true", frames[1], maxInFlight, closeCount)
}
