package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestFMShutdown_UploadOwnsRecvUntilDeclaredBodyCompletes(t *testing.T) {
	// Given
	directory := t.TempDir()
	uploadPath := filepath.Join(directory, "upload.bin")
	uploadCommand := make([]byte, 9, 9+len(uploadPath))
	uploadCommand[0] = 2
	binary.BigEndian.PutUint64(uploadCommand[1:9], 4)
	uploadCommand = append(uploadCommand, uploadPath...)
	bodyRecvEntered := make(chan struct{})
	releaseBody := make(chan struct{})
	completionSent := make(chan struct{})
	nextCommandRecv := make(chan struct{})
	stream := &fmTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.Equal(data, []byte("NZUP")) {
			close(completionSent)
		}
		return nil
	}
	stream.recvHook = func(call int) (*pb.IOStreamData, error) {
		switch call {
		case 1:
			return &pb.IOStreamData{Data: uploadCommand}, nil
		case 2:
			close(bodyRecvEntered)
			<-releaseBody
			return &pb.IOStreamData{Data: []byte("body")}, nil
		case 3:
			close(nextCommandRecv)
			return nil, io.EOF
		default:
			return nil, errors.New("unexpected duplicate Recv")
		}
	}
	done := runFMHandlerForTest(t, fmTestRun{parent: context.Background(), stream: stream, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, bodyRecvEntered, "exclusive upload body Recv")

	// When
	select {
	case <-nextCommandRecv:
		t.Fatal("command loop called Recv while upload owned the receiver")
	default:
	}
	close(releaseBody)
	awaitStreamSignal(t, completionSent, "legacy NZUP completion")
	awaitStreamSignal(t, nextCommandRecv, "command Recv after upload completion")
	awaitStreamSignal(t, done, "FM upload shutdown")

	// Then
	content, err := os.ReadFile(uploadPath)
	if err != nil {
		t.Fatalf("read upload: %v", err)
	}
	if !bytes.Equal(content, []byte("body")) {
		t.Fatalf("upload content = %x, want 626f6479", content)
	}
	observation := stream.observation()
	if observation.recvCount != 3 || observation.closeCount != 1 {
		t.Fatalf("upload ownership recv=%d close=%d, want 3/1", observation.recvCount, observation.closeCount)
	}
}

func TestFMShutdown_RemoteEOFJoinsDownloadBeforeCloseSend(t *testing.T) {
	// Given
	downloadPath := filepath.Join(t.TempDir(), "blocked-download.bin")
	if err := os.WriteFile(downloadPath, []byte("blocked"), 0o644); err != nil {
		t.Fatalf("write download: %v", err)
	}
	downloadSendEntered := make(chan struct{})
	downloadSendReturned := make(chan struct{})
	stream := &fmTestStream{}
	stream.sendHook = func(data []byte) error {
		if len(data) == 12 && bytes.Equal(data[:4], []byte("NZTD")) {
			close(downloadSendEntered)
			<-stream.ctx.Done()
			close(downloadSendReturned)
			return context.Cause(stream.ctx)
		}
		return nil
	}
	stream.recvHook = func(call int) (*pb.IOStreamData, error) {
		if call == 1 {
			return &pb.IOStreamData{Data: append([]byte{1}, downloadPath...)}, nil
		}
		<-downloadSendEntered
		return nil, io.EOF
	}
	stream.closeHook = func() error {
		select {
		case <-downloadSendReturned:
			return nil
		default:
			return errors.New("CloseSend ran before download producer returned")
		}
	}

	// When
	done := runFMHandlerForTest(t, fmTestRun{parent: context.Background(), stream: stream, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, done, "FM remote EOF shutdown")

	// Then
	observation := stream.observation()
	if observation.closeCount != 1 || observation.maxWriteInFlight != 1 || observation.sendAfterClose != 0 {
		t.Fatalf("remote EOF cleanup: max=%d close=%d late=%d", observation.maxWriteInFlight, observation.closeCount, observation.sendAfterClose)
	}
}

func TestFMSendFailure_CancelsRecvAndJoinsDownloadsBeforeClose(t *testing.T) {
	// Given
	directory := t.TempDir()
	pathA := filepath.Join(directory, "a.bin")
	pathB := filepath.Join(directory, "b.bin")
	for _, path := range []string{pathA, pathB} {
		if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
			t.Fatalf("write download: %v", err)
		}
	}
	sendErr := errors.New("FM send failed")
	stream := &fmTestStream{}
	stream.sendHook = func(data []byte) error {
		if len(data) == 12 && bytes.Equal(data[:4], []byte("NZTD")) {
			return sendErr
		}
		return nil
	}
	stream.recvHook = func(call int) (*pb.IOStreamData, error) {
		switch call {
		case 1:
			return &pb.IOStreamData{Data: append([]byte{1}, pathA...)}, nil
		case 2:
			return &pb.IOStreamData{Data: append([]byte{1}, pathB...)}, nil
		default:
			<-stream.ctx.Done()
			return nil, context.Cause(stream.ctx)
		}
	}
	stream.closeHook = func() error {
		return nil
	}

	// When
	done := runFMHandlerForTest(t, fmTestRun{
		parent:            context.Background(),
		stream:            stream,
		keepaliveInterval: time.Hour,
	})
	awaitStreamSignal(t, done, "FM Send failure shutdown")

	// Then
	observation := stream.observation()
	if !errors.Is(context.Cause(stream.ctx), sendErr) {
		t.Fatalf("stream cancel cause = %v, want %v", context.Cause(stream.ctx), sendErr)
	}
	if observation.maxWriteInFlight != 1 || observation.closeCount != 1 || observation.sendAfterClose != 0 {
		t.Fatalf("Send failure cleanup: max=%d close=%d late=%d", observation.maxWriteInFlight, observation.closeCount, observation.sendAfterClose)
	}
}

func TestFMShutdown_SessionCancellationStopsRecvAndJoinsDownloadBeforeClose(t *testing.T) {
	// Given
	parent, cancelParent := context.WithCancel(context.Background())
	downloadPath := filepath.Join(t.TempDir(), "session-cancel.bin")
	if err := os.WriteFile(downloadPath, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write download: %v", err)
	}
	downloadSendEntered := make(chan struct{})
	downloadSendReturned := make(chan struct{})
	recvEntered := make(chan struct{})
	stream := &fmTestStream{}
	stream.sendHook = func(data []byte) error {
		if len(data) == 12 && bytes.Equal(data[:4], []byte("NZTD")) {
			close(downloadSendEntered)
			<-stream.ctx.Done()
			close(downloadSendReturned)
			return context.Cause(stream.ctx)
		}
		return nil
	}
	stream.recvHook = func(call int) (*pb.IOStreamData, error) {
		if call == 1 {
			return &pb.IOStreamData{Data: append([]byte{1}, downloadPath...)}, nil
		}
		close(recvEntered)
		<-stream.ctx.Done()
		return nil, context.Cause(stream.ctx)
	}
	stream.closeHook = func() error {
		select {
		case <-downloadSendReturned:
			return nil
		default:
			return errors.New("CloseSend ran before canceled download returned")
		}
	}
	done := runFMHandlerForTest(t, fmTestRun{parent: parent, stream: stream, keepaliveInterval: time.Hour})
	awaitStreamSignal(t, downloadSendEntered, "session-cancel download Send")
	awaitStreamSignal(t, recvEntered, "session-cancel command Recv")

	// When
	cancelParent()
	awaitStreamSignal(t, done, "FM session cancellation shutdown")

	// Then
	observation := stream.observation()
	if observation.recvCount != 2 || observation.closeCount != 1 || observation.maxWriteInFlight != 1 || observation.sendAfterClose != 0 {
		t.Fatalf("session cancellation: recv=%d close=%d max=%d late=%d", observation.recvCount, observation.closeCount, observation.maxWriteInFlight, observation.sendAfterClose)
	}
}
