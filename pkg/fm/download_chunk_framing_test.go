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
	// The system's wording for a missing file differs per platform, so the
	// expected text is whatever opening the same path reports.
	openFailureText := func(path string) string {
		_, err := openDownloadFile(path)
		if err == nil {
			t.Fatalf("opening %s succeeded, want a failure", path)
		}
		return err.Error()
	}
	missingPath := filepath.Join(t.TempDir(), "missing.bin")
	cases := []struct {
		name     string
		path     string
		wantText string
	}{
		{"missing file", missingPath, openFailureText(missingPath)},
		{"missing file with a long path", longestMissingPath, openFailureText(longestMissingPath)},
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
			wantFrame := append(append([]byte(nil), errorIdentifier...), testCase.wantText...)
			if !bytes.Equal(frames[0], wantFrame) {
				t.Fatalf("frame = %q, want %q", frames[0], wantFrame)
			}
			if len(frames[0]) > frontendMaxErrorFrameBytes {
				t.Fatalf("error frame has %d bytes, the frontend would write it into the file", len(frames[0]))
			}
		})
	}
}

// shortReadingDownloadFile returns at most a few hundred bytes per Read, the way
// FUSE and some network file systems do.
type shortReadingDownloadFile struct {
	*os.File
	bytesPerRead int
}

func (f *shortReadingDownloadFile) Read(buffer []byte) (int, error) {
	if len(buffer) > f.bytesPerRead {
		buffer = buffer[:f.bytesPerRead]
	}
	return f.File.Read(buffer)
}

// The chunk size must not depend on how much the file system returns per read.
func TestTask_DownloadSendsFullChunksWhenTheFileSystemReadsShort(t *testing.T) {
	content := make([]byte, 2*downloadChunkBytes+5)
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("generate content: %v", err)
	}
	// With short reads every small piece used to be sent as its own frame; one
	// that begins with the error marker reads as an error frame to the frontend.
	copy(content[700:], errorIdentifier)
	path := filepath.Join(t.TempDir(), "download.bin")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write download fixture: %v", err)
	}
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)
	task.openFile = func(path string) (downloadFile, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return &shortReadingDownloadFile{File: file, bytesPerRead: 700}, nil
	}

	if err := task.download(path); err != nil {
		t.Fatalf("download returned %v", err)
	}

	frames := stream.frames()
	if len(frames) != 4 {
		t.Fatalf("sent %d frames, want a header, two full chunks and the tail", len(frames))
	}
	wantLengths := []int{downloadChunkBytes, downloadChunkBytes, 5}
	var received []byte
	for index, chunk := range frames[1:] {
		if len(chunk) != wantLengths[index] {
			t.Fatalf("chunk %d has %d bytes, want %d", index, len(chunk), wantLengths[index])
		}
		received = append(received, chunk...)
	}
	if !bytes.Equal(received, content) {
		t.Fatal("chunks do not reassemble into the file content")
	}
}

// changedSizeDownloadFile reports one size and holds different content, the way
// a file does that is appended to or truncated after the download began.
type changedSizeDownloadFile struct {
	*os.File
	reportedSize int64
}

func (f *changedSizeDownloadFile) Stat() (os.FileInfo, error) {
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return changedSizeFileInfo{FileInfo: info, size: f.reportedSize}, nil
}

type changedSizeFileInfo struct {
	os.FileInfo
	size int64
}

func (i changedSizeFileInfo) Size() int64 { return i.size }

func downloadWithReportedSize(t *testing.T, content []byte, reportedSize int64) [][]byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "changing.log")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write download fixture: %v", err)
	}
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)
	task.openFile = func(path string) (downloadFile, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return &changedSizeDownloadFile{File: file, reportedSize: reportedSize}, nil
	}
	if err := task.download(path); err != nil {
		t.Fatalf("download returned %v", err)
	}
	return stream.frames()
}

// The peer counts bytes up to the size in the header; there is no end frame.
// A log that grew during the download used to be sent to its new end, and the
// surplus reached the peer as if it were the next protocol frames.
func TestTask_DownloadOfAGrowingFileStopsAtTheDeclaredSize(t *testing.T) {
	frames := downloadWithReportedSize(t, []byte("123456789"), 5)

	if len(frames) != 2 {
		t.Fatalf("sent %d frames, want the header and one chunk", len(frames))
	}
	if declared := binary.BigEndian.Uint64(frames[0][4:]); declared != 5 {
		t.Fatalf("header declares %d bytes, want 5", declared)
	}
	if string(frames[1]) != "12345" {
		t.Fatalf("content = %q, want exactly the declared 5 bytes", frames[1])
	}
}

// A file that became shorter used to end silently, leaving the peer waiting for
// bytes that never come.
func TestTask_DownloadOfATruncatedFileEndsWithAnError(t *testing.T) {
	frames := downloadWithReportedSize(t, []byte("1234"), 10)

	if len(frames) != 3 {
		t.Fatalf("sent %d frames, want the header, the available content and an error", len(frames))
	}
	if string(frames[1]) != "1234" {
		t.Fatalf("content = %q, want the 4 bytes that exist", frames[1])
	}
	wantError := append(append([]byte(nil), errorIdentifier...), "file changed during download: sent 4 of 10 bytes"...)
	if !bytes.Equal(frames[2], wantError) {
		t.Fatalf("last frame = %q, want %q", frames[2], wantError)
	}
}
