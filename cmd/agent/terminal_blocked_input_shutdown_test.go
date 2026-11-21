package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

// A large paste into a terminal whose foreground program does not read its
// input blocks the write to the PTY. The receiver is then no longer in Recv
// and the program prints nothing, so neither worker noticed the browser going
// away: the session and its shell stayed until the agent restarted.
func TestTerminalShutdown_StreamFailureEndsSessionWhoseInputWriteIsBlocked(t *testing.T) {
	tty := newTerminalTestPTY()
	tty.writeBlockedUntilClose = make(chan struct{}, 1)
	pasteDelivered := make(chan struct{})
	var received atomic.Int32
	var streamGone atomic.Bool
	stream := &terminalTestStream{
		recvHook: func() (*pb.IOStreamData, error) {
			if received.Add(1) == 1 {
				return &pb.IOStreamData{Data: append([]byte{0}, "pasted text"...)}, nil
			}
			<-pasteDelivered
			return nil, errors.New("recv after the paste must not be reached while the write is blocked")
		},
		// Keepalive frames are empty; once the browser is gone they fail.
		sendHook: func(data []byte) error {
			if len(data) == 0 && streamGone.Load() {
				return errors.New("stream closed by the dashboard")
			}
			return nil
		},
	}
	done := runTerminalHandlerForTest(t, terminalTestRun{
		parent:            context.Background(),
		stream:            stream,
		tty:               tty,
		keepaliveInterval: 10 * time.Millisecond,
	})
	awaitStreamSignal(t, tty.writeBlockedUntilClose, "the paste reaching the PTY")

	streamGone.Store(true)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(pasteDelivered)
		t.Fatal("the terminal session outlived its stream while the input write was blocked")
	}
	close(pasteDelivered)
	if tty.closes() != 1 {
		t.Fatalf("the PTY was closed %d time(s), want once", tty.closes())
	}
}
