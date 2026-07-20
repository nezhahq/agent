package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

func TestFMStreamOwnership_SerializesDownloadListAndKeepaliveAndClosesOnce(t *testing.T) {
	// Given
	directory := t.TempDir()
	downloadPath := filepath.Join(directory, "download.bin")
	downloadBody := []byte("whole-download-frame")
	if err := os.WriteFile(downloadPath, downloadBody, 0o644); err != nil {
		t.Fatalf("write download fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "listed.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write list fixture: %v", err)
	}
	firstBusinessSend := make(chan struct{})
	releaseFirstBusinessSend := make(chan struct{})
	allFramesSent := make(chan struct{})
	keepaliveStarted := make(chan struct{})
	var firstBusiness bool
	stream := &fmTestStream{}
	stream.sendHook = func(data []byte) error {
		if bytes.HasPrefix(data, []byte{0xff, 0x05, 0xff, 0x05}) {
			return nil
		}
		if !firstBusiness {
			firstBusiness = true
			close(firstBusinessSend)
			<-releaseFirstBusinessSend
		}
		if len(stream.observation().frames) == 5 {
			select {
			case <-allFramesSent:
			default:
				close(allFramesSent)
			}
		}
		return nil
	}
	stream.recvHook = func(call int) (*pb.IOStreamData, error) {
		switch call {
		case 1:
			return &pb.IOStreamData{Data: append([]byte{1}, downloadPath...)}, nil
		case 2:
			return &pb.IOStreamData{Data: append([]byte{0}, directory...)}, nil
		default:
			<-allFramesSent
			return nil, io.EOF
		}
	}
	done := runFMHandlerForTest(t, fmTestRun{
		parent:            context.Background(),
		stream:            stream,
		keepaliveInterval: time.Hour,
		startKeepalive: func(owner *ioStreamWriteOwner, _ time.Duration) error {
			go func() {
				<-firstBusinessSend
				close(keepaliveStarted)
				_ = owner.Send(&pb.IOStreamData{})
			}()
			return nil
		},
	})
	awaitStreamSignal(t, firstBusinessSend, "first FM business Send")
	awaitStreamSignal(t, keepaliveStarted, "FM keepalive attempt")

	// When
	close(releaseFirstBusinessSend)
	awaitStreamSignal(t, done, "FM ownership shutdown")

	// Then
	observation := stream.observation()
	if observation.maxWriteInFlight != 1 || observation.closeCount != 1 || observation.sendAfterClose != 0 {
		t.Fatalf("FM ownership: max=%d close=%d send_after_close=%d", observation.maxWriteInFlight, observation.closeCount, observation.sendAfterClose)
	}
	assertFMWholeFrames(t, observation.frames, downloadBody)
}

func assertFMWholeFrames(t *testing.T, frames [][]byte, downloadBody []byte) {
	t.Helper()
	var attach, header, chunk, list, keepalive bool
	for _, frame := range frames {
		switch {
		case bytes.Equal(frame, append([]byte{0xff, 0x05, 0xff, 0x05}, []byte("fm-test")...)):
			attach = true
		case len(frame) == 12 && bytes.Equal(frame[:4], []byte("NZTD")):
			header = true
		case bytes.Equal(frame, downloadBody):
			chunk = true
		case len(frame) >= 4 && bytes.Equal(frame[:4], []byte("NZFN")):
			list = true
		case len(frame) == 0:
			keepalive = true
		}
	}
	if !attach || !header || !chunk || !list || !keepalive {
		t.Fatalf("FM whole-frame set incomplete: frames=%x", frames)
	}
}
