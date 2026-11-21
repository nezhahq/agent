package fm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const downloadChunkBytes = 1024 * 1024

// The dashboard frontend tells file content from an error frame by size alone,
// because chunks carry no header: during a download a frame is content when it
// is exactly the bytes still owed or larger than a short error text (16 KiB).
// That only holds while every chunk but the last is a full 1 MiB read and the
// last is exactly the remainder. These tests pin that framing.
func TestTask_DownloadSendsFullChunksThenExactRemainder(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"one byte", 1},
		{"shorter than a frame marker", 3},
		{"one byte below a chunk", downloadChunkBytes - 1},
		{"exactly one chunk", downloadChunkBytes},
		{"one chunk and a two byte tail", downloadChunkBytes + 2},
		{"exactly three chunks", 3 * downloadChunkBytes},
		{"three chunks and a tail", 3*downloadChunkBytes + 7},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			content := make([]byte, testCase.size)
			if _, err := rand.Read(content); err != nil {
				t.Fatalf("generate content: %v", err)
			}
			// Every chunk begins with the error marker: content must pass through untouched.
			for offset := 0; offset+len(errorIdentifier) <= len(content); offset += downloadChunkBytes {
				copy(content[offset:], errorIdentifier)
			}
			path := filepath.Join(t.TempDir(), "download.bin")
			if err := os.WriteFile(path, content, 0o600); err != nil {
				t.Fatalf("write download fixture: %v", err)
			}
			stream := &taskIsolationStream{}
			task := newTaskIsolationTask(stream)

			if err := task.download(path); err != nil {
				t.Fatalf("download returned %v", err)
			}

			frames := stream.frames()
			wantChunks := (testCase.size + downloadChunkBytes - 1) / downloadChunkBytes
			if len(frames) != 1+wantChunks {
				t.Fatalf("sent %d frames, want a header and %d chunks", len(frames), wantChunks)
			}
			wantHeader := binary.BigEndian.AppendUint64(append([]byte(nil), fileIdentifier...), uint64(testCase.size))
			if !bytes.Equal(frames[0], wantHeader) {
				t.Fatalf("header = %x, want %x", frames[0], wantHeader)
			}
			remaining := testCase.size
			var received []byte
			for index, chunk := range frames[1:] {
				wantLength := min(remaining, downloadChunkBytes)
				if len(chunk) != wantLength {
					t.Fatalf("chunk %d has %d bytes, want %d", index, len(chunk), wantLength)
				}
				remaining -= len(chunk)
				received = append(received, chunk...)
			}
			if !bytes.Equal(received, content) {
				t.Fatal("chunks do not reassemble into the file content")
			}
		})
	}
}

func TestTask_DownloadFailureIsOneShortErrorFrame(t *testing.T) {
	// The frontend treats frames above this size as file content.
	const frontendMaxErrorFrameBytes = 16 * 1024
	emptyFile := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatalf("write empty fixture: %v", err)
	}
	longestMissingPath := filepath.Join(t.TempDir(), strings.Repeat("d", 200), strings.Repeat("f", 255))
	cases := []struct {
		name     string
		path     string
		wantText string
	}{
		{"missing file", filepath.Join(t.TempDir(), "missing.bin"), "no such file or directory"},
		{"missing file with a long path", longestMissingPath, "no such file or directory"},
		{"empty file", emptyFile, "requested file is empty"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			stream := &taskIsolationStream{}
			task := newTaskIsolationTask(stream)

			if err := task.download(testCase.path); err != nil {
				t.Fatalf("download returned %v", err)
			}

			frames := stream.frames()
			if len(frames) != 1 {
				t.Fatalf("sent %d frames, want exactly one error frame", len(frames))
			}
			if !bytes.HasPrefix(frames[0], errorIdentifier) {
				t.Fatalf("frame = %q, want an error frame", frames[0])
			}
			if !bytes.Contains(frames[0], []byte(testCase.wantText)) {
				t.Fatalf("error frame %q does not carry %q", frames[0], testCase.wantText)
			}
			if len(frames[0]) > frontendMaxErrorFrameBytes {
				t.Fatalf("error frame has %d bytes, the frontend would write it into the file", len(frames[0]))
			}
		})
	}
}
