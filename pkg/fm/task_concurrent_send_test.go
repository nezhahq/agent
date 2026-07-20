package fm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

type serialTaskSender struct {
	mu           sync.Mutex
	frames       [][]byte
	downloadBody []byte
	downloadSent chan struct{}
	downloadOnce sync.Once
}

func (s *serialTaskSender) Send(message *pb.IOStreamData) error {
	s.mu.Lock()
	frame := append([]byte(nil), message.GetData()...)
	s.frames = append(s.frames, frame)
	s.mu.Unlock()
	if bytes.Equal(frame, s.downloadBody) {
		s.downloadOnce.Do(func() { close(s.downloadSent) })
	}
	return nil
}

func (s *serialTaskSender) snapshot() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.frames))
	for index := range s.frames {
		frames[index] = append([]byte(nil), s.frames[index]...)
	}
	return frames
}

func TestTask_ConcurrentSendUsesProvidedSenderForListAndDownload(t *testing.T) {
	// Given
	directory := t.TempDir()
	downloadPath := filepath.Join(directory, "download.bin")
	downloadBody := []byte("download-body")
	if err := os.WriteFile(downloadPath, downloadBody, 0o644); err != nil {
		t.Fatalf("write download: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "listed.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write list fixture: %v", err)
	}
	sender := &serialTaskSender{downloadBody: downloadBody, downloadSent: make(chan struct{})}
	task := NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         sender,
		UploadReceiver: &legacyUploadReceiver{},
		Printf:         func(string, ...interface{}) {},
	})

	// When
	if err := task.DoTask(&pb.IOStreamData{Data: append([]byte{1}, downloadPath...)}); err != nil {
		t.Fatalf("start download: %v", err)
	}
	if err := task.DoTask(&pb.IOStreamData{Data: append([]byte{0}, directory...)}); err != nil {
		t.Fatalf("list directory: %v", err)
	}
	select {
	case <-sender.downloadSent:
	case <-time.After(5 * time.Second):
		t.Fatal("download body was not sent before shutdown")
	}
	task.Shutdown(context.Canceled)

	// Then
	frames := sender.snapshot()
	var header, chunk, list bool
	for _, frame := range frames {
		switch {
		case len(frame) == 12 && bytes.Equal(frame[:4], []byte("NZTD")):
			header = true
		case bytes.Equal(frame, downloadBody):
			chunk = true
		case len(frame) >= 4 && bytes.Equal(frame[:4], []byte("NZFN")):
			list = true
		}
	}
	if !header || !chunk || !list {
		t.Fatalf("provided Sender did not receive whole list/download frames: %x", frames)
	}
}

var _ Sender = (*serialTaskSender)(nil)
