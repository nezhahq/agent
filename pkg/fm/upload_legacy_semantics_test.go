package fm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

type legacyUploadReceiver struct {
	frames []*pb.IOStreamData
	err    error
}

func (r *legacyUploadReceiver) Recv() (*pb.IOStreamData, error) {
	if len(r.frames) == 0 {
		return nil, r.err
	}
	frame := r.frames[0]
	r.frames = r.frames[1:]
	return frame, nil
}

type legacyUploadSender struct {
	frames [][]byte
}

type blockingLegacyUploadReceiver struct {
	entered chan struct{}
	release chan error
	once    sync.Once
}

func (r *blockingLegacyUploadReceiver) Recv() (*pb.IOStreamData, error) {
	r.once.Do(func() { close(r.entered) })
	return nil, <-r.release
}

func (s *legacyUploadSender) Send(message *pb.IOStreamData) error {
	s.frames = append(s.frames, append([]byte(nil), message.GetData()...))
	return nil
}

func TestTask_UploadPreservesLegacyOversendBehavior(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "oversend.bin")
	payload := []byte("body-plus-extra")
	sender := &legacyUploadSender{}
	receiver := &legacyUploadReceiver{frames: []*pb.IOStreamData{{Data: payload}}, err: io.EOF}
	task := NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         sender,
		UploadReceiver: receiver,
		Printf:         func(string, ...interface{}) {},
	})
	command := uploadCommand(target, 4)

	// When
	err := task.DoTask(&pb.IOStreamData{Data: command})

	// Then
	if err != nil {
		t.Fatalf("legacy oversend returned error: %v", err)
	}
	content, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read oversend target: %v", readErr)
	}
	if !bytes.Equal(content, payload) {
		t.Fatalf("legacy oversend content = %x, want full frame %x", content, payload)
	}
	if len(sender.frames) != 1 || !bytes.Equal(sender.frames[0], []byte("NZUP")) {
		t.Fatalf("legacy oversend completion = %x, want NZUP", sender.frames)
	}
}

func TestTask_UploadPreservesLegacyTruncatedFileOnRecvError(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "truncated.bin")
	recvErr := errors.New("legacy upload receive failed")
	sender := &legacyUploadSender{}
	receiver := &legacyUploadReceiver{
		frames: []*pb.IOStreamData{{Data: []byte("part")}},
		err:    recvErr,
	}
	task := NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         sender,
		UploadReceiver: receiver,
		Printf:         func(string, ...interface{}) {},
	})
	command := uploadCommand(target, 8)

	// When
	err := task.DoTask(&pb.IOStreamData{Data: command})

	// Then
	if !errors.Is(err, recvErr) {
		t.Fatalf("legacy truncated upload error = %v, want %v", err, recvErr)
	}
	content, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read truncated target: %v", readErr)
	}
	if !bytes.Equal(content, []byte("part")) {
		t.Fatalf("legacy truncated content = %x, want 70617274", content)
	}
	wantError := append([]byte("NERR"), []byte(recvErr.Error())...)
	if len(sender.frames) != 1 || !bytes.Equal(sender.frames[0], wantError) {
		t.Fatalf("legacy truncated error frame = %x, want %x", sender.frames, wantError)
	}
}

func TestTask_UploadTruncatesExistingFileBeforeFirstRecvAndHasNoSizeCap(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "existing.bin")
	if err := os.WriteFile(target, []byte("existing-content"), 0o644); err != nil {
		t.Fatalf("write existing target: %v", err)
	}
	recvErr := errors.New("stop legacy huge upload")
	receiver := &blockingLegacyUploadReceiver{entered: make(chan struct{}), release: make(chan error)}
	sender := &legacyUploadSender{}
	task := NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         sender,
		UploadReceiver: receiver,
		Printf:         func(string, ...interface{}) {},
	})
	uploadDone := make(chan error, 1)

	// When
	go func() {
		uploadDone <- task.DoTask(&pb.IOStreamData{Data: uploadCommand(target, math.MaxUint64)})
	}()
	<-receiver.entered

	// Then
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target while first Recv is blocked: %v", err)
	}
	if len(content) != 0 {
		t.Fatalf("existing upload target was not truncated before first Recv: %x", content)
	}
	receiver.release <- recvErr
	if err := <-uploadDone; !errors.Is(err, recvErr) {
		t.Fatalf("huge declared upload error = %v, want %v", err, recvErr)
	}
	wantError := append([]byte("NERR"), []byte(recvErr.Error())...)
	if len(sender.frames) != 1 || !bytes.Equal(sender.frames[0], wantError) {
		t.Fatalf("huge declared upload response = %x, want %x", sender.frames, wantError)
	}
}

func uploadCommand(path string, size uint64) []byte {
	command := make([]byte, 9, 9+len(path))
	command[0] = byte(commandUpload)
	binary.BigEndian.PutUint64(command[1:9], size)
	return append(command, path...)
}
