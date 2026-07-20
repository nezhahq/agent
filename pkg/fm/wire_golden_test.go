package fm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

type legacyFMWireStream struct {
	pb.NezhaService_IOStreamClient
	mu           sync.Mutex
	recv         []*pb.IOStreamData
	sent         [][]byte
	expectedSent int
	observed     chan struct{}
	once         sync.Once
}

func legacyWireMismatch(actual, golden []byte) error {
	if bytes.Equal(actual, golden) {
		return nil
	}
	return errors.New("wire frame differs from literal golden")
}

func (s *legacyFMWireStream) Send(data *pb.IOStreamData) error {
	s.mu.Lock()
	s.sent = append(s.sent, append([]byte(nil), data.GetData()...))
	count := len(s.sent)
	s.mu.Unlock()
	if s.observed != nil && count == s.expectedSent {
		s.once.Do(func() { close(s.observed) })
	}
	return nil
}

func (s *legacyFMWireStream) Recv() (*pb.IOStreamData, error) {
	if len(s.recv) == 0 {
		return nil, io.EOF
	}
	data := s.recv[0]
	s.recv = s.recv[1:]
	return data, nil
}

func (s *legacyFMWireStream) frames() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.sent))
	for i := range s.sent {
		frames[i] = append([]byte(nil), s.sent[i]...)
	}
	return frames
}

func TestLegacyFMWire_ListPathAndEntryMatchLiteralGolden(t *testing.T) {
	// Given
	t.Chdir(t.TempDir())
	const listPath = "wire-list"
	if err := os.Mkdir(listPath, 0o755); err != nil {
		t.Fatalf("create list fixture: %v", err)
	}
	if err := os.WriteFile(listPath+"/a", []byte("x"), 0o644); err != nil {
		t.Fatalf("create file entry: %v", err)
	}
	if err := os.Mkdir(listPath+"/d", 0o755); err != nil {
		t.Fatalf("create directory entry: %v", err)
	}
	command := []byte{0x00, 0x77, 0x69, 0x72, 0x65, 0x2d, 0x6c, 0x69, 0x73, 0x74}
	stream := &legacyFMWireStream{}
	task := newLegacyWireTask(stream)
	want := []byte{
		0x4e, 0x5a, 0x46, 0x4e,
		0x00, 0x00, 0x00, 0x09,
		0x77, 0x69, 0x72, 0x65, 0x2d, 0x6c, 0x69, 0x73, 0x74,
		0x00, 0x01, 0x61,
		0x01, 0x01, 0x64,
	}

	// When
	task.DoTask(&pb.IOStreamData{Data: command})

	// Then
	frames := stream.frames()
	if len(frames) != 1 || !bytes.Equal(frames[0], want) {
		t.Fatalf("list request or NZFN entries changed: got %x want %x", frames, want)
	}
	t.Logf("legacy NZFN list frame=%x", frames[0])
}

func TestLegacyFMWire_DownloadCommandHeaderAndChunkMatchLiteralGoldens(t *testing.T) {
	// Given
	t.Chdir(t.TempDir())
	const downloadPath = "legacy-fm-wire-golden-download.bin"
	if err := os.WriteFile(downloadPath, []byte{0xde, 0xad, 0xbe, 0xef}, 0o644); err != nil {
		t.Fatalf("create download fixture: %v", err)
	}
	command := []byte{
		0x01,
		0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2d, 0x66, 0x6d, 0x2d,
		0x77, 0x69, 0x72, 0x65, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e,
		0x2d, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x62, 0x69, 0x6e,
	}
	wantHeader := []byte{
		0x4e, 0x5a, 0x54, 0x44,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	}
	wantChunk := []byte{0xde, 0xad, 0xbe, 0xef}
	observed := make(chan struct{})
	stream := &legacyFMWireStream{expectedSent: 2, observed: observed}
	task := newLegacyWireTask(stream)

	// When
	task.DoTask(&pb.IOStreamData{Data: command})
	select {
	case <-observed:
	case <-time.After(5 * time.Second):
		t.Fatal("download frames were not emitted before deadline")
	}

	// Then
	frames := stream.frames()
	if len(frames) != 2 || !bytes.Equal(frames[0], wantHeader) || !bytes.Equal(frames[1], wantChunk) {
		t.Fatalf("download command, NZTD header, or chunk changed: got %x", frames)
	}
	t.Logf("legacy download header=%x chunk=%x", frames[0], frames[1])
}

func TestLegacyFMWire_ErrorFrameMatchesLiteralGolden(t *testing.T) {
	// Given
	want := []byte{0x4e, 0x45, 0x52, 0x52, 0x62, 0x6f, 0x6f, 0x6d}

	// When
	got := CreateErr(errors.New("boom"))

	// Then
	if !bytes.Equal(got, want) {
		t.Fatalf("NERR frame changed: got %x want %x", got, want)
	}
}

func TestLegacyFMWire_UploadCommandAndCompletionMatchLiteralGolden(t *testing.T) {
	// Given
	t.Chdir(t.TempDir())
	const uploadPath = "legacy-fm-wire-golden-upload.bin"
	command := []byte{
		0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2d, 0x66, 0x6d, 0x2d,
		0x77, 0x69, 0x72, 0x65, 0x2d, 0x67, 0x6f, 0x6c, 0x64, 0x65, 0x6e,
		0x2d, 0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x62, 0x69, 0x6e,
	}
	stream := &legacyFMWireStream{recv: []*pb.IOStreamData{{Data: []byte{0xde, 0xad, 0xbe, 0xef}}}}
	task := newLegacyWireTask(stream)

	// When
	task.DoTask(&pb.IOStreamData{Data: command})

	// Then
	content, err := os.ReadFile(uploadPath)
	if err != nil {
		t.Fatalf("read uploaded fixture: %v", err)
	}
	if !bytes.Equal(content, []byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("upload command size/path framing changed: got content %x", content)
	}
	frames := stream.frames()
	if len(frames) != 1 || !bytes.Equal(frames[0], []byte{0x4e, 0x5a, 0x55, 0x50}) {
		t.Fatalf("upload completion changed: got frames %x", frames)
	}
	t.Logf("legacy upload content=%x completion=%x", content, frames[0])
}

func TestLegacyFMWire_MutatedVectorsAreDetected(t *testing.T) {
	t.Chdir(t.TempDir())
	var encoded bytes.Buffer
	actualHeader := CreateFile(&encoded, 0x0102030405060708)
	headerGolden := []byte{
		0x4e, 0x5a, 0x54, 0x44,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}
	if !bytes.Equal(actualHeader, headerGolden) {
		t.Fatalf("production NZTD header does not match literal golden: got %x", actualHeader)
	}
	completionGolden := []byte{0x4e, 0x5a, 0x55, 0x50}
	uploadCommand := []byte{
		0x02,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74, 0x69, 0x6f, 0x6e,
		0x2d, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x62, 0x69, 0x6e,
	}
	completionStream := &legacyFMWireStream{recv: []*pb.IOStreamData{{Data: []byte{0xaa}}}}
	_ = newLegacyWireTask(completionStream).DoTask(&pb.IOStreamData{Data: uploadCommand})
	completionFrames := completionStream.frames()
	if len(completionFrames) != 1 || !bytes.Equal(completionFrames[0], completionGolden) {
		t.Fatalf("production upload completion does not match literal NZUP: got %x", completionFrames)
	}
	completionActual := completionFrames[0]
	tests := []struct {
		name   string
		golden []byte
		mutate func([]byte) []byte
	}{
		{name: "one byte magic", golden: headerGolden, mutate: func(frame []byte) []byte { frame[0] = 0x4f; return frame }},
		{name: "short header", golden: headerGolden, mutate: func(frame []byte) []byte { return frame[:len(frame)-1] }},
		{name: "little endian size", golden: headerGolden, mutate: func(frame []byte) []byte {
			copy(frame[4:], []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01})
			return frame
		}},
		{name: "completion marker", golden: completionGolden, mutate: func(frame []byte) []byte { frame[3] = 0x51; return frame }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := actualHeader
			if test.name == "completion marker" {
				actual = completionActual
			}
			corruptedActual := test.mutate(append([]byte(nil), actual...))
			if err := legacyWireMismatch(corruptedActual, test.golden); err == nil {
				t.Fatalf("literal comparator accepted corrupted production frame: %x", corruptedActual)
			}
		})
	}
}

func newLegacyWireTask(stream *legacyFMWireStream) *Task {
	return NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         stream,
		UploadReceiver: stream,
		Printf:         func(string, ...interface{}) {},
	})
}
