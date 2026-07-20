package fm

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

type taskIsolationStream struct {
	pb.NezhaService_IOStreamClient

	mu           sync.Mutex
	sent         [][]byte
	expectedSent int
	sentObserved chan struct{}
	sentOnce     sync.Once

	recvEntered chan struct{}
	recvCalls   chan struct{}
	recvRelease chan *pb.IOStreamData
	recvOnce    sync.Once
}

func (s *taskIsolationStream) Send(data *pb.IOStreamData) error {
	s.mu.Lock()
	s.sent = append(s.sent, append([]byte(nil), data.GetData()...))
	count := len(s.sent)
	s.mu.Unlock()
	if s.sentObserved != nil && count == s.expectedSent {
		s.sentOnce.Do(func() { close(s.sentObserved) })
	}
	return nil
}

func (s *taskIsolationStream) Recv() (*pb.IOStreamData, error) {
	s.recvOnce.Do(func() { close(s.recvEntered) })
	if s.recvCalls != nil {
		s.recvCalls <- struct{}{}
	}
	return <-s.recvRelease, nil
}

func (s *taskIsolationStream) frames() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.sent))
	for i := range s.sent {
		frames[i] = append([]byte(nil), s.sent[i]...)
	}
	return frames
}

func awaitTaskSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func TestTask_DoTaskDownloadKeepsOriginalPathWhenNextTaskArrives(t *testing.T) {
	// Given
	dir := t.TempDir()
	pathA := filepath.Join(dir, "download-a.bin")
	pathB := filepath.Join(dir, "download-b.bin")
	contentA := []byte("content-from-a")
	contentB := []byte("different-content-from-b")
	if err := os.WriteFile(pathA, contentA, 0o644); err != nil {
		t.Fatalf("write download A: %v", err)
	}
	if err := os.WriteFile(pathB, contentB, 0o644); err != nil {
		t.Fatalf("write download B: %v", err)
	}
	observed := make(chan struct{})
	stream := &taskIsolationStream{expectedSent: 2, sentObserved: observed}
	task := newTaskIsolationTask(stream)
	openEntered := make(chan struct{})
	openRelease := make(chan struct{})
	task.openFile = func(path string) (downloadFile, error) {
		close(openEntered)
		<-openRelease
		return os.Open(path)
	}
	commandA := append([]byte{1}, []byte(pathA)...)
	commandB := append([]byte{0xff}, []byte(pathB)...)

	// When
	task.DoTask(&pb.IOStreamData{Data: commandA})
	awaitTaskSignal(t, openEntered, "download A open barrier")
	task.DoTask(&pb.IOStreamData{Data: commandB})
	close(openRelease)
	awaitTaskSignal(t, observed, "download A frames")

	// Then
	frames := stream.frames()
	wantHeader := make([]byte, 12)
	copy(wantHeader, []byte("NZTD"))
	binary.BigEndian.PutUint64(wantHeader[4:], uint64(len(contentA)))
	if len(frames) != 2 || !bytes.Equal(frames[0], wantHeader) || !bytes.Equal(frames[1], contentA) {
		t.Fatalf("download A was overwritten by command B: frames=%x want_chunk=%x", frames, contentA)
	}
}

func TestTask_DoTaskDownloadKeepsOriginalPathWhenCallerReusesFrame(t *testing.T) {
	// Given
	dir := t.TempDir()
	pathA := filepath.Join(dir, "caller-buffer-a.bin")
	pathB := filepath.Join(dir, "caller-buffer-b.bin")
	contentA := []byte("immutable-command-a")
	contentB := []byte("mutable-command-bb")
	if len(pathA) != len(pathB) {
		t.Fatalf("test paths must have equal lengths: %q %q", pathA, pathB)
	}
	if err := os.WriteFile(pathA, contentA, 0o644); err != nil {
		t.Fatalf("write caller buffer A: %v", err)
	}
	if err := os.WriteFile(pathB, contentB, 0o644); err != nil {
		t.Fatalf("write caller buffer B: %v", err)
	}
	observed := make(chan struct{})
	stream := &taskIsolationStream{expectedSent: 2, sentObserved: observed}
	task := newTaskIsolationTask(stream)
	openEntered := make(chan struct{})
	openRelease := make(chan struct{})
	task.openFile = func(path string) (downloadFile, error) {
		close(openEntered)
		<-openRelease
		return os.Open(path)
	}
	command := append([]byte{1}, []byte(pathA)...)

	// When
	task.DoTask(&pb.IOStreamData{Data: command})
	awaitTaskSignal(t, openEntered, "caller mutation open barrier")
	command[0] = 0xff
	copy(command[1:], pathB)
	close(openRelease)
	awaitTaskSignal(t, observed, "download from copied command")

	// Then
	frames := stream.frames()
	if len(frames) != 2 || !bytes.Equal(frames[1], contentA) {
		t.Fatalf("download path aliased caller frame: frames=%x want_chunk=%x", frames, contentA)
	}
}

func TestTask_DeferredSliceParserWouldObserveCallerMutation(t *testing.T) {
	// Given
	pathA := "deferred-path-a"
	pathB := "deferred-path-b"
	command := append([]byte{1}, pathA...)
	parseRelease := make(chan struct{})
	type deferredCommand struct {
		opcode byte
		path   string
	}
	observedCommand := make(chan deferredCommand, 1)
	go func(frame []byte) {
		<-parseRelease
		observedCommand <- deferredCommand{opcode: frame[0], path: string(frame[1:])}
	}(command)

	// When
	command[0] = 0xff
	copy(command[1:], pathB)
	close(parseRelease)

	// Then
	if got := <-observedCommand; got.opcode != 0xff || got.path != pathB {
		t.Fatalf("deferred slice parser observed opcode=%x path=%q, want opcode=ff path=%q", got.opcode, got.path, pathB)
	}
}

func TestTask_UploadUsesLocalFrames(t *testing.T) {
	// Given
	dir := t.TempDir()
	targetA := filepath.Join(dir, "local-upload-a.bin")
	targetB := filepath.Join(dir, "local-upload-b.bin")
	if len(targetA) != len(targetB) {
		t.Fatalf("test paths must have equal lengths: %q %q", targetA, targetB)
	}
	firstPayload := []byte("upload-")
	secondPayload := []byte("owned-frame")
	wantPayload := append(append([]byte(nil), firstPayload...), secondPayload...)
	command := make([]byte, 9, 9+len(targetA))
	command[0] = 2
	binary.BigEndian.PutUint64(command[1:9], uint64(len(wantPayload)))
	command = append(command, targetA...)
	recvEntered := make(chan struct{})
	recvCalls := make(chan struct{}, 2)
	recvRelease := make(chan *pb.IOStreamData)
	sentObserved := make(chan struct{})
	stream := &taskIsolationStream{
		expectedSent: 1,
		sentObserved: sentObserved,
		recvEntered:  recvEntered,
		recvCalls:    recvCalls,
		recvRelease:  recvRelease,
	}
	task := newTaskIsolationTask(stream)

	// When
	go task.DoTask(&pb.IOStreamData{Data: command})
	awaitTaskSignal(t, recvEntered, "upload Recv entry")
	awaitTaskSignal(t, recvCalls, "upload first Recv call")
	command[0] = 0xff
	binary.BigEndian.PutUint64(command[1:9], uint64(len(firstPayload)))
	copy(command[9:], targetB)
	task.DoTask(&pb.IOStreamData{Data: []byte{0xff}})
	recvRelease <- &pb.IOStreamData{Data: firstPayload}
	awaitTaskSignal(t, recvCalls, "upload second Recv call from parsed size")
	recvRelease <- &pb.IOStreamData{Data: secondPayload}
	awaitTaskSignal(t, sentObserved, "upload completion")

	// Then
	content, err := os.ReadFile(targetA)
	if err != nil {
		t.Fatalf("read upload target: %v", err)
	}
	if !bytes.Equal(content, wantPayload) {
		t.Fatalf("upload consumed mutated metadata or another command: got %x want %x", content, wantPayload)
	}
	if _, err := os.Stat(targetB); !os.IsNotExist(err) {
		t.Fatalf("mutated upload path was used: stat error = %v", err)
	}
	frames := stream.frames()
	if len(frames) != 1 || !bytes.Equal(frames[0], []byte("NZUP")) {
		t.Fatalf("upload completion changed: got %x want 4e5a5550", frames)
	}
}

func newTaskIsolationTask(stream *taskIsolationStream) *Task {
	return NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         stream,
		UploadReceiver: stream,
		Printf:         func(string, ...interface{}) {},
	})
}
