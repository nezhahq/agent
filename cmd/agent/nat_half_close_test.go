package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

type natScriptedReadConn struct {
	net.Conn
	payload []byte
	err     error
	once    sync.Once
}

func (c *natScriptedReadConn) Read(buffer []byte) (int, error) {
	read := 0
	readErr := error(nil)
	c.once.Do(func() {
		read = copy(buffer, c.payload)
		readErr = c.err
	})
	if read > 0 || readErr != nil {
		return read, readErr
	}
	return c.Conn.Read(buffer)
}

func TestNATWire_PayloadAndEOFSendTailThenLegacyError(t *testing.T) {
	testNATReadResultFrames(t, []byte{0x00, 0xff, 't'}, io.EOF)
}

func TestNATWire_PayloadAndReadErrorSendTailThenLegacyError(t *testing.T) {
	testNATReadResultFrames(t, []byte("tail"), errors.New("sentinel read failure"))
}

func TestNATWire_ZeroAndEOFDoesNotSendEmptyPayload(t *testing.T) {
	testNATReadResultFrames(t, nil, io.EOF)
}

func testNATReadResultFrames(t *testing.T, payload []byte, readErr error) {
	t.Helper()
	local, peer := net.Pipe()
	conn := newNATObservedConn(&natScriptedReadConn{Conn: local, payload: payload, err: readErr})
	t.Cleanup(func() { _ = peer.Close() })
	remoteDone := make(chan struct{})
	closeObserved := make(chan struct{})
	stream := &natTestStream{recvHook: func() (*pb.IOStreamData, error) {
		<-remoteDone
		return nil, io.EOF
	}, closeHook: func() error { close(closeObserved); return nil }}
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(), stream: stream,
		dial:              func(context.Context, string, string) (net.Conn, error) { return conn, nil },
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, closeObserved, "NAT local read CloseSend")
	close(remoteDone)
	awaitStreamSignal(t, done, "NAT read-result shutdown")

	frames, _, closeCount, _ := stream.observation()
	want := [][]byte{{0xff, 0x05, 0xff, 0x05, 'n', 'a', 't', '-', 't', 'e', 's', 't'}}
	if len(payload) > 0 {
		want = append(want, payload)
	}
	want = append(want, []byte(readErr.Error()))
	if len(frames) != len(want) {
		t.Fatalf("NAT read-result frames=%q want=%q", frames, want)
	}
	for index := range want {
		if !bytes.Equal(frames[index], want[index]) {
			t.Fatalf("NAT read-result frame %d=%x want=%x", index, frames[index], want[index])
		}
	}
	if closeCount != 1 {
		t.Fatalf("CloseSend count=%d want=1", closeCount)
	}
}
