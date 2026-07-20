package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestNATStreamOwnership_SerializesKeepaliveAndTCPReaderAndClosesOnce(t *testing.T) {
	// Given
	local, peer := net.Pipe()
	conn := newNATObservedConn(local)
	t.Cleanup(func() { _ = peer.Close() })
	payload := []byte{0x00, 0xff, 'n', 'a', 't'}
	payloadSendEntered := make(chan struct{})
	keepaliveEntered := make(chan struct{})
	releasePayloadSend := make(chan struct{})
	stream := &natTestStream{}
	stream.sendHook = func(data []byte) error {
		switch {
		case bytes.Equal(data, payload):
			close(payloadSendEntered)
			<-releasePayloadSend
		case len(data) == 0:
			close(keepaliveEntered)
		}
		return nil
	}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-keepaliveEntered
		return nil, io.EOF
	}
	done := runNATHandlerForTest(t, natTestRun{
		parent: context.Background(),
		stream: stream,
		dial: func(context.Context, string, string) (net.Conn, error) {
			return conn, nil
		},
		keepaliveInterval: time.Hour,
		startKeepalive: func(owner *ioStreamWriteOwner, _ time.Duration) error {
			go func() {
				<-payloadSendEntered
				_ = owner.Send(&pb.IOStreamData{Data: []byte{}})
			}()
			return nil
		},
	})
	writeDone := make(chan error, 1)
	go func() {
		_, err := peer.Write(payload)
		writeDone <- err
	}()
	awaitStreamSignal(t, payloadSendEntered, "NAT TCP reader Send entry")

	// When
	close(releasePayloadSend)
	awaitStreamSignal(t, keepaliveEntered, "serialized NAT keepalive Send")
	awaitStreamSignal(t, done, "NAT ownership shutdown")

	// Then
	if err := <-writeDone; err != nil {
		t.Fatalf("write local NAT payload: %v", err)
	}
	frames, maxInFlight, closeCount, recvCount := stream.observation()
	if len(frames) < 3 || !bytes.Equal(frames[1], payload) || maxInFlight != 1 || closeCount != 1 || recvCount != 1 || conn.closes() != 1 {
		t.Fatalf("NAT ownership: frames=%x max=%d close=%d recv=%d conn_close=%d", frames, maxInFlight, closeCount, recvCount, conn.closes())
	}
}
