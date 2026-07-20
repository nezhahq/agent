package main

import (
	"context"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

// gRPC Go ClientStream does not allow concurrent SendMsg invocations
// (https://pkg.go.dev/google.golang.org/grpc#ClientStream).
// handleFsTransferTask spawns ioStreamKeepAlive on the same client stream
// that fsTransferUpload / fsTransferDownload use to send NZTU / NZTD / NZTC /
// NZTO / NZTE frames; a slow >30s transfer therefore lets the keepalive
// goroutine race the protocol goroutine on stream.Send. The fix path must
// route every Send through a per-stream serial sender so concurrent callers
// queue rather than race.
func TestSerialIOStreamSender_GuaranteesAtMostOneSendInFlight(t *testing.T) {
	raw := newIOStreamFixture(context.Background(), streamCallAllowance{send: 2})
	sender := newSerialIOStreamSender(raw)
	firstExited := make(chan error, 1)
	secondExited := make(chan error, 1)
	go func() { firstExited <- sender.Send(&pb.IOStreamData{Data: []byte("first")}) }()
	raw.waitWriteEntered(t, streamWriteSend)
	go func() { secondExited <- sender.Send(&pb.IOStreamData{Data: []byte("second")}) }()
	select {
	case operation := <-raw.writeEntered:
		t.Fatalf("second write entered before first release: %q", operation)
	default:
	}
	raw.releaseWrite(streamWriteSend, nil)
	raw.waitWriteEntered(t, streamWriteSend)
	raw.releaseWrite(streamWriteSend, nil)
	if err := awaitStreamOperationResult(t, firstExited); err != nil {
		t.Fatalf("first Send returned error: %v", err)
	}
	if err := awaitStreamOperationResult(t, secondExited); err != nil {
		t.Fatalf("second Send returned error: %v", err)
	}
	if observation := raw.observe(); observation.maxWriteInFlight != 1 {
		t.Fatalf("serialIOStreamSender max-in-flight=%d, want 1", observation.maxWriteInFlight)
	}
}

func TestSerialIOStreamSender_PreservesFrameBytes(t *testing.T) {
	// Given
	raw := newIOStreamFixture(context.Background(), streamCallAllowance{send: 1})
	sender := newSerialIOStreamSender(raw)
	want := []byte{0x4e, 0x5a, 0x54, 0x45, 0x62, 0x61, 0x64}
	sendExited := make(chan error, 1)

	// When
	go func() { sendExited <- sender.Send(&pb.IOStreamData{Data: append([]byte(nil), want...)}) }()
	raw.waitWriteEntered(t, streamWriteSend)
	raw.releaseWrite(streamWriteSend, nil)

	// Then
	if err := awaitStreamOperationResult(t, sendExited); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	messages := raw.sentMessages()
	if len(messages) != 1 {
		t.Fatalf("serialized sender message count=%d, want 1", len(messages))
	}
	if string(messages[0].GetData()) != string(want) {
		t.Fatalf("serialized sender changed frame: got %x want %x", messages[0].GetData(), want)
	}
}

func TestSerialIOStreamSender_RecvRemainsOutsideSendSerialization(t *testing.T) {
	// Given
	streamContext, cancelStream := context.WithCancel(context.Background())
	defer cancelStream()
	raw := newIOStreamFixture(streamContext, streamCallAllowance{send: 1, recv: 1})
	sender := newSerialIOStreamSender(raw)
	wrapped := streamWithSerialSender{stream: raw, sender: sender}
	sendExited := make(chan error, 1)
	go func() { sendExited <- wrapped.Send(&pb.IOStreamData{Data: []byte("blocked")}) }()
	raw.waitWriteEntered(t, streamWriteSend)
	recvExited := make(chan error, 1)
	go func() {
		_, err := wrapped.Recv()
		recvExited <- err
	}()

	// When
	raw.waitRecvEntered(t)
	raw.releaseRecv(&pb.IOStreamData{Data: []byte("peer")}, nil)

	// Then
	if err := awaitStreamOperationResult(t, recvExited); err != nil {
		t.Fatalf("Recv returned error: %v", err)
	}
	raw.releaseWrite(streamWriteSend, nil)
	if err := awaitStreamOperationResult(t, sendExited); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
}

// keepalive 与协议帧共用同一个底层 stream 时，必须经由同一个串行化器，
// 不允许独立持有底层 stream 直接 Send，否则又会出现并发写入。
func TestSerialIOStreamSender_KeepaliveSharesSerializerWithProtocolFrames(t *testing.T) {
	raw := newIOStreamFixture(context.Background(), streamCallAllowance{send: 2})
	sender := newSerialIOStreamSender(raw)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		serializedKeepAlive(ctx, sender, time.Nanosecond)
	}()
	raw.waitWriteEntered(t, streamWriteSend)
	businessExited := make(chan error, 1)
	go func() { businessExited <- sender.Send(&pb.IOStreamData{Data: []byte("data")}) }()
	cancel()
	select {
	case operation := <-raw.writeEntered:
		t.Fatalf("business write entered during keepalive Send: %q", operation)
	default:
	}
	raw.releaseWrite(streamWriteSend, nil)
	raw.waitWriteEntered(t, streamWriteSend)
	raw.releaseWrite(streamWriteSend, nil)
	awaitStreamSignal(t, done, "serialized keepalive completion")
	if err := awaitStreamOperationResult(t, businessExited); err != nil {
		t.Fatalf("business Send returned error: %v", err)
	}
	if observation := raw.observe(); observation.maxWriteInFlight != 1 {
		t.Fatalf("keepalive max-in-flight=%d, want 1", observation.maxWriteInFlight)
	}
}
