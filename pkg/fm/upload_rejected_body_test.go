package fm

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

// Upload content has no frame header and the peer keeps sending it until it
// sees an error. When the target could not be created the upload used to
// return at once, and the content frames that followed were parsed as
// commands: one that begins with the upload opcode creates or empties whatever
// file its bytes name.
func TestTask_UploadThatCannotCreateItsTargetConsumesTheDeclaredBody(t *testing.T) {
	directory := t.TempDir()
	// A directory with the target's name makes creating the file fail.
	target := filepath.Join(directory, "taken-by-a-directory")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("create blocking directory: %v", err)
	}
	// File content that reads as "upload a 0 byte file to <victim>".
	victim := filepath.Join(directory, "victim.txt")
	if err := os.WriteFile(victim, []byte("must stay"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	contentReadingAsUploadCommand := binary.BigEndian.AppendUint64([]byte{byte(commandUpload)}, 0)
	contentReadingAsUploadCommand = append(contentReadingAsUploadCommand, victim...)
	firstPiece, secondPiece := contentReadingAsUploadCommand[:9], contentReadingAsUploadCommand[9:]

	stream := &taskIsolationStream{recvEntered: make(chan struct{}), recvRelease: make(chan *pb.IOStreamData, 2)}
	stream.recvRelease <- &pb.IOStreamData{Data: firstPiece}
	stream.recvRelease <- &pb.IOStreamData{Data: secondPiece}
	task := newTaskIsolationTask(stream)

	finished := make(chan error, 1)
	go func() { finished <- task.upload(target, uint64(len(contentReadingAsUploadCommand))) }()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("upload returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not return after its whole body had arrived")
	}

	if left := len(stream.recvRelease); left != 0 {
		t.Fatalf("%d content frame(s) were left for the command loop to parse", left)
	}
	frames := stream.frames()
	if len(frames) != 1 || !bytes.HasPrefix(frames[0], errorIdentifier) {
		t.Fatalf("frames = %q, want exactly one error frame", frames)
	}
	// What the command loop would have done with the leftover frame.
	for len(stream.recvRelease) > 0 {
		task.DoTask(<-stream.recvRelease)
	}
	kept, err := os.ReadFile(victim)
	if err != nil || string(kept) != "must stay" {
		t.Fatalf("victim file = %q, %v; want it untouched", kept, err)
	}
}
