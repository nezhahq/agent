package fm

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

type pathCommandConsumer func(*Task, string) error
type uploadCommandConsumer func(*Task, string, uint64) error

var (
	_ pathCommandConsumer   = (*Task).listDir
	_ pathCommandConsumer   = (*Task).download
	_ uploadCommandConsumer = (*Task).upload
)

func TestTask_RejectsMalformedFrameWithoutPanic(t *testing.T) {
	invalidFrame := []byte("NERRdata is invalid")
	tests := []struct {
		name      string
		message   *pb.IOStreamData
		wantFrame []byte
	}{
		{name: "nil message", message: nil, wantFrame: invalidFrame},
		{name: "empty command", message: &pb.IOStreamData{}, wantFrame: invalidFrame},
		{name: "unknown operation preserves no response", message: &pb.IOStreamData{Data: []byte{0xff}}},
	}
	for commandLength := 1; commandLength < 9; commandLength++ {
		command := make([]byte, commandLength)
		command[0] = 2
		tests = append(tests, struct {
			name      string
			message   *pb.IOStreamData
			wantFrame []byte
		}{
			name:      "short upload length " + string(rune('0'+commandLength)),
			message:   &pb.IOStreamData{Data: command},
			wantFrame: invalidFrame,
		})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			stream := &taskIsolationStream{}
			task := newTaskIsolationTask(stream)

			// When
			task.DoTask(test.message)

			// Then
			frames := stream.frames()
			if test.wantFrame == nil {
				if len(frames) != 0 {
					t.Fatalf("legacy no-response behavior changed: got %x", frames)
				}
				return
			}
			if len(frames) != 1 || !bytes.Equal(frames[0], test.wantFrame) {
				t.Fatalf("malformed response = %x, want %x", frames, test.wantFrame)
			}
		})
	}
}

func TestTask_RejectsMalformedFrame_OpOnlyCommandsUseLegacyBehavior(t *testing.T) {
	t.Run("list falls back to home directory", func(t *testing.T) {
		// Given
		currentUser, err := user.Current()
		if err != nil {
			t.Fatalf("resolve current user: %v", err)
		}
		stream := &taskIsolationStream{}
		task := newTaskIsolationTask(stream)

		// When
		task.DoTask(&pb.IOStreamData{Data: []byte{0}})

		// Then
		frames := stream.frames()
		if len(frames) != 1 || len(frames[0]) < 8 || !bytes.Equal(frames[0][:4], []byte("NZFN")) {
			t.Fatalf("op-only list response = %x, want one NZFN frame", frames)
		}
		pathLength := binary.BigEndian.Uint32(frames[0][4:8])
		pathEnd := 8 + int(pathLength)
		if pathEnd > len(frames[0]) {
			t.Fatalf("op-only list path length %d exceeds frame length %d", pathLength, len(frames[0]))
		}
		wantPath := currentUser.HomeDir + string(filepath.Separator)
		if gotPath := string(frames[0][8:pathEnd]); gotPath != wantPath {
			t.Fatalf("op-only list path = %q, want legacy fallback %q", gotPath, wantPath)
		}
	})

	t.Run("download returns legacy open error", func(t *testing.T) {
		// Given
		observed := make(chan struct{})
		stream := &taskIsolationStream{expectedSent: 1, sentObserved: observed}
		task := newTaskIsolationTask(stream)

		// When
		task.DoTask(&pb.IOStreamData{Data: []byte{1}})
		awaitTaskSignal(t, observed, "op-only download error")

		// Then
		frames := stream.frames()
		if len(frames) != 1 || len(frames[0]) <= 4 || !bytes.Equal(frames[0][:4], []byte("NERR")) {
			t.Fatalf("op-only download response = %x, want one non-empty NERR frame", frames)
		}
	})

	t.Run("upload without path returns legacy create error", func(t *testing.T) {
		// Given
		stream := &taskIsolationStream{}
		task := newTaskIsolationTask(stream)
		command := make([]byte, 9)
		command[0] = 2

		// When
		task.DoTask(&pb.IOStreamData{Data: command})

		// Then
		frames := stream.frames()
		if len(frames) != 1 || len(frames[0]) <= 4 || !bytes.Equal(frames[0][:4], []byte("NERR")) {
			t.Fatalf("pathless upload response = %x, want one non-empty NERR frame", frames)
		}
	})
}

func TestTask_DefaultOpenFileUsesOSOpen(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "default-open.bin")
	wantContent := []byte("default-os-open")
	if err := os.WriteFile(path, wantContent, 0o644); err != nil {
		t.Fatalf("write default open fixture: %v", err)
	}
	observed := make(chan struct{})
	stream := &taskIsolationStream{expectedSent: 2, sentObserved: observed}
	task := newTaskIsolationTask(stream)

	// When
	task.DoTask(&pb.IOStreamData{Data: append([]byte{1}, path...)})
	awaitTaskSignal(t, observed, "default os.Open download")

	// Then
	frames := stream.frames()
	if len(frames) != 2 || !bytes.Equal(frames[1], wantContent) {
		t.Fatalf("default open download = %x, want content %x", frames, wantContent)
	}
}
