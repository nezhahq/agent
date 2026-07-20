package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

// blockingRecvStream blocks the first Recv until release is closed, letting the
// test observe whether fsTransferUpload holds the path stripe lock across the
// network receive window.
type blockingRecvStream struct {
	pb.NezhaService_IOStreamClient
	release chan struct{}
	recvHit chan struct{}
	payload []byte
	served  bool
}

func (s *blockingRecvStream) Send(*pb.IOStreamData) error { return nil }
func (s *blockingRecvStream) CloseSend() error            { return nil }
func (s *blockingRecvStream) Header() (metadata.MD, error) {
	return metadata.MD{}, nil
}
func (s *blockingRecvStream) Trailer() metadata.MD { return metadata.MD{} }

func (s *blockingRecvStream) Recv() (*pb.IOStreamData, error) {
	if !s.served {
		s.served = true
		close(s.recvHit)
		<-s.release
		return &pb.IOStreamData{Data: s.payload}, nil
	}
	return &pb.IOStreamData{}, nil
}

// A stalled upload must not hold the per-path stripe lock while it waits for
// bytes from the network. Holding it across stream.Recv lets a slow/malicious
// caller block unrelated fs.write / fs.transfer writers that hash to the same
// stripe for up to the 5-minute IO timeout — a remotely triggerable DoS.
// The lock's own contract says it is only held "across a short
// check-then-rename window".
func TestFsTransferUpload_DoesNotHoldStripeLockDuringRecv(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "out.bin")

	stream := &blockingRecvStream{
		release: make(chan struct{}),
		recvHit: make(chan struct{}),
		payload: []byte("hello"),
	}
	req := &model.FsTransferRequest{
		Op:   model.MCPFsTransferOpUpload,
		Path: target,
		Size: int64(len(stream.payload)),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		fsTransferUpload(stream, req)
	}()

	// Wait until upload is parked inside Recv.
	select {
	case <-stream.recvHit:
	case <-time.After(5 * time.Second):
		t.Fatal("upload never reached Recv")
	}

	// The stripe lock for this path must be acquirable right now.
	got := make(chan struct{})
	go func() {
		unlock := fsPathMu.lock(target)
		unlock()
		close(got)
	}()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		close(stream.release)
		<-done
		t.Fatal("stripe lock was held during Recv — DoS window still open")
	}

	close(stream.release)
	<-done

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("target not written: %v", err)
	}
	if string(data) != string(stream.payload) {
		t.Fatalf("content mismatch: got %q want %q", data, stream.payload)
	}
}
