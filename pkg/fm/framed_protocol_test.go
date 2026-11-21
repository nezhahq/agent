package fm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/nezhahq/agent/proto"
)

type namedDirEntry struct {
	fs.DirEntry
	name      string
	directory bool
}

func (e namedDirEntry) Name() string { return e.name }
func (e namedDirEntry) IsDir() bool  { return e.directory }

type listedEntry struct {
	name      string
	directory bool
}

// decodeListingPages is what a peer does with listing pages: it checks every
// page's framing and returns the entries in order.
func decodeListingPages(t *testing.T, pages [][]byte, wantDir string) []listedEntry {
	t.Helper()
	var entries []listedEntry
	for index, page := range pages {
		if len(page) > framedFrameMaxBytes {
			t.Fatalf("page %d has %d bytes, the dashboard relay would split it", index, len(page))
		}
		if !bytes.HasPrefix(page, listingPageIdentifier) {
			t.Fatalf("page %d does not start with the listing marker: %x", index, page[:4])
		}
		last := page[4]&listingLastPageFlag != 0
		if last != (index == len(pages)-1) {
			t.Fatalf("page %d of %d has last flag = %t", index, len(pages), last)
		}
		dirLength := int(binary.BigEndian.Uint32(page[5:9]))
		if got := string(page[9 : 9+dirLength]); got != wantDir {
			t.Fatalf("page %d names directory %q, want %q", index, got, wantDir)
		}
		rest := page[9+dirLength:]
		for len(rest) > 0 {
			nameLength := int(binary.BigEndian.Uint16(rest[1:3]))
			entries = append(entries, listedEntry{name: string(rest[3 : 3+nameLength]), directory: rest[0] == 1})
			rest = rest[3+nameLength:]
		}
	}
	return entries
}

func negotiateFramedProtocol(t *testing.T, task *Task, stream *taskIsolationStream) {
	t.Helper()
	if err := task.DoTask(&pb.IOStreamData{Data: []byte{byte(commandHello), framedProtocolVersion}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	frames := stream.frames()
	want := append(append([]byte(nil), helloIdentifier...), framedProtocolVersion)
	if len(frames) != 1 || !bytes.Equal(frames[0], want) {
		t.Fatalf("hello acknowledgement = %x, want %x", frames, want)
	}
}

// A peer that only speaks the old protocol gets the old protocol, also when it
// greets with a lower version.
func TestHello_OlderPeerKeepsTheUnframedProtocol(t *testing.T) {
	path := filepath.Join(t.TempDir(), "download.bin")
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)
	if err := task.DoTask(&pb.IOStreamData{Data: []byte{byte(commandHello), 1}}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	if err := task.download(path); err != nil {
		t.Fatalf("download: %v", err)
	}

	frames := stream.frames()
	if len(frames) != 3 {
		t.Fatalf("sent %d frames, want the acknowledgement, the header and one unframed chunk", len(frames))
	}
	if want := append(append([]byte(nil), helloIdentifier...), 1); !bytes.Equal(frames[0], want) {
		t.Fatalf("acknowledgement = %x, want version 1 (%x)", frames[0], want)
	}
	if string(frames[2]) != "content" {
		t.Fatalf("chunk = %q, want the raw content of the old protocol", frames[2])
	}
}

func TestHello_WithoutAVersionIsInvalid(t *testing.T) {
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)

	if err := task.DoTask(&pb.IOStreamData{Data: []byte{byte(commandHello)}}); err != nil {
		t.Fatalf("hello: %v", err)
	}

	frames := stream.frames()
	if len(frames) != 1 || !bytes.HasPrefix(frames[0], errorIdentifier) {
		t.Fatalf("frames = %q, want one error frame", frames)
	}
	if task.framed.Load() {
		t.Fatal("a malformed hello switched the session to the framed protocol")
	}
}

// In the framed protocol every frame names its type, so content that starts
// with the error marker cannot be mistaken for an error, and the end frame
// tells the peer the download is over.
func TestFramedDownload_EveryFrameIsTypedAndTheEndIsAnnounced(t *testing.T) {
	const chunkContentBytes = framedFrameMaxBytes - 4
	for _, size := range []int{1, 3, chunkContentBytes - 1, chunkContentBytes, chunkContentBytes + 1, 3*chunkContentBytes + 7} {
		content := make([]byte, size)
		if _, err := rand.Read(content); err != nil {
			t.Fatal(err)
		}
		for offset := 0; offset+len(errorIdentifier) <= len(content); offset += chunkContentBytes {
			copy(content[offset:], errorIdentifier)
		}
		path := filepath.Join(t.TempDir(), "download.bin")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		stream := &taskIsolationStream{}
		task := newTaskIsolationTask(stream)
		negotiateFramedProtocol(t, task, stream)

		if err := task.download(path); err != nil {
			t.Fatalf("size %d: download returned %v", size, err)
		}

		frames := stream.frames()[1:]
		wantChunks := (size + chunkContentBytes - 1) / chunkContentBytes
		if len(frames) != wantChunks+2 {
			t.Fatalf("size %d: sent %d frames, want a header, %d chunks and an end frame", size, len(frames), wantChunks)
		}
		if want := binary.BigEndian.AppendUint64(append([]byte(nil), fileIdentifier...), uint64(size)); !bytes.Equal(frames[0], want) {
			t.Fatalf("size %d: header = %x, want %x", size, frames[0], want)
		}
		var received []byte
		for index, chunk := range frames[1 : len(frames)-1] {
			if !bytes.HasPrefix(chunk, downloadChunkIdentifier) {
				t.Fatalf("size %d: chunk %d does not start with the chunk marker", size, index)
			}
			if len(chunk) > framedFrameMaxBytes {
				t.Fatalf("size %d: chunk %d has %d bytes, the dashboard relay would split it", size, index, len(chunk))
			}
			if index < wantChunks-1 && len(chunk) != framedFrameMaxBytes {
				t.Fatalf("size %d: chunk %d has %d bytes, want a full frame", size, index, len(chunk))
			}
			received = append(received, chunk[4:]...)
		}
		if !bytes.Equal(received, content) {
			t.Fatalf("size %d: chunks do not reassemble into the file content", size)
		}
		if want := binary.BigEndian.AppendUint64(append([]byte(nil), downloadEndIdentifier...), uint64(size)); !bytes.Equal(frames[len(frames)-1], want) {
			t.Fatalf("size %d: last frame = %x, want the end frame %x", size, frames[len(frames)-1], want)
		}
	}
}

// The old protocol cannot carry an empty file: its peer waits for content that
// never comes. With an end frame it can.
func TestFramedDownload_EmptyFileIsAHeaderAndAnEndFrame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)
	negotiateFramedProtocol(t, task, stream)

	if err := task.download(path); err != nil {
		t.Fatalf("download returned %v", err)
	}

	frames := stream.frames()[1:]
	wantHeader := binary.BigEndian.AppendUint64(append([]byte(nil), fileIdentifier...), 0)
	wantEnd := binary.BigEndian.AppendUint64(append([]byte(nil), downloadEndIdentifier...), 0)
	if len(frames) != 2 || !bytes.Equal(frames[0], wantHeader) || !bytes.Equal(frames[1], wantEnd) {
		t.Fatalf("frames = %x, want %x and %x", frames, wantHeader, wantEnd)
	}
}

func TestFramedDownload_TruncatedFileEndsWithAnErrorAndNoEndFrame(t *testing.T) {
	path := filepath.Join(t.TempDir(), "changing.log")
	if err := os.WriteFile(path, []byte("1234"), 0o600); err != nil {
		t.Fatal(err)
	}
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)
	negotiateFramedProtocol(t, task, stream)
	task.openFile = func(path string) (downloadFile, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		return &changedSizeDownloadFile{File: file, reportedSize: 10}, nil
	}

	if err := task.download(path); err != nil {
		t.Fatalf("download returned %v", err)
	}

	frames := stream.frames()[1:]
	if len(frames) != 3 {
		t.Fatalf("sent %d frames, want the header, one chunk and an error", len(frames))
	}
	if want := append(append([]byte(nil), downloadChunkIdentifier...), "1234"...); !bytes.Equal(frames[1], want) {
		t.Fatalf("chunk = %q, want %q", frames[1], want)
	}
	if !bytes.HasPrefix(frames[2], errorIdentifier) || !bytes.Contains(frames[2], []byte("sent 4 of 10 bytes")) {
		t.Fatalf("last frame = %q, want the error about the changed file", frames[2])
	}
}

// The old listing put a name's length in one byte and the whole directory in
// one frame. Longer names shifted every entry after them, and a listing above
// the dashboard's 1 MiB relay buffer arrived in pieces nobody could parse.
func TestFramedListing_CarriesLongNamesAndSplitsLargeDirectoriesIntoPages(t *testing.T) {
	var entries []fs.DirEntry
	var want []listedEntry
	add := func(name string, directory bool) {
		entries = append(entries, namedDirEntry{name: name, directory: directory})
		want = append(want, listedEntry{name: name, directory: directory})
	}
	add(strings.Repeat("长", 200), false) // 600 bytes, legal on NTFS and APFS
	add("after-the-long-name.txt", false)
	add("a-directory", true)
	for index := 0; index < 7000; index++ {
		add(strings.Repeat("n", 195)+string(rune('a'+index%26))+strings.Repeat("0", index%5), index%7 == 0)
	}

	pages := createListingPages("/srv/data", entries)

	if len(pages) < 2 {
		t.Fatalf("a listing of about 1.4 MiB was put into %d page(s)", len(pages))
	}
	got := decodeListingPages(t, pages, "/srv/data")
	if len(got) != len(want) {
		t.Fatalf("decoded %d entries, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("entry %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

func TestFramedListing_EmptyDirectoryIsOneLastPage(t *testing.T) {
	directory := t.TempDir()
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)
	negotiateFramedProtocol(t, task, stream)

	if err := task.listDir(directory); err != nil {
		t.Fatalf("listDir: %v", err)
	}

	pages := stream.frames()[1:]
	if len(pages) != 1 {
		t.Fatalf("sent %d pages, want one", len(pages))
	}
	if entries := decodeListingPages(t, pages, directory); len(entries) != 0 {
		t.Fatalf("entries = %+v, want none", entries)
	}
}

func TestFramedListing_ListsARealDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "file.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	stream := &taskIsolationStream{}
	task := newTaskIsolationTask(stream)
	negotiateFramedProtocol(t, task, stream)

	if err := task.listDir(directory); err != nil {
		t.Fatalf("listDir: %v", err)
	}

	got := decodeListingPages(t, stream.frames()[1:], directory)
	want := []listedEntry{{name: "file.txt"}, {name: "nested", directory: true}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("entries = %+v, want %+v", got, want)
	}
}

// The old protocol cannot represent a name above 255 bytes. Writing it anyway
// wrapped the length byte and shifted every later entry; it is left out.
func TestLegacyListing_LeavesOutNamesItCannotRepresent(t *testing.T) {
	entries := []fs.DirEntry{
		namedDirEntry{name: "before.txt"},
		namedDirEntry{name: strings.Repeat("长", 200)},
		namedDirEntry{name: "after", directory: true},
	}

	listing := createLegacyListing("/srv", entries)

	want := append([]byte(nil), fileNameIdentifier...)
	want = binary.BigEndian.AppendUint32(want, 4)
	want = append(want, "/srv"...)
	want = append(want, 0, byte(len("before.txt")))
	want = append(want, "before.txt"...)
	want = append(want, 1, byte(len("after")))
	want = append(want, "after"...)
	if !bytes.Equal(listing, want) {
		t.Fatalf("listing = %q, want %q", listing, want)
	}
}
