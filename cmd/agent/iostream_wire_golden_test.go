package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
)

type iostreamWireClient struct {
	pb.NezhaServiceClient
	stream pb.NezhaService_IOStreamClient
}

func (c *iostreamWireClient) IOStream(context.Context, ...grpc.CallOption) (pb.NezhaService_IOStreamClient, error) {
	return c.stream, nil
}

type iostreamWireStream struct {
	pb.NezhaService_IOStreamClient
	mu   sync.Mutex
	sent [][]byte
	recv func() (*pb.IOStreamData, error)
}

func (s *iostreamWireStream) Send(data *pb.IOStreamData) error {
	frame := append([]byte(nil), data.GetData()...)
	s.mu.Lock()
	s.sent = append(s.sent, frame)
	s.mu.Unlock()
	return nil
}

func (s *iostreamWireStream) Recv() (*pb.IOStreamData, error) {
	if s.recv == nil {
		return nil, io.EOF
	}
	return s.recv()
}

func (s *iostreamWireStream) CloseSend() error {
	return nil
}

func (s *iostreamWireStream) Context() context.Context {
	return context.Background()
}

func mcpWireMatches(actual, golden []byte) bool { return bytes.Equal(actual, golden) }

func assertWireMutationDetected(t *testing.T, name string, actual, golden []byte, mutate func([]byte) []byte) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		corruptedActual := mutate(append([]byte(nil), actual...))
		if !mcpWireMatches(corruptedActual, golden) {
			return
		}
		t.Fatalf("literal comparator accepted corrupted production frame: %x", corruptedActual)
	})
}

func (s *iostreamWireStream) frames() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	frames := make([][]byte, len(s.sent))
	for i := range s.sent {
		frames[i] = append([]byte(nil), s.sent[i]...)
	}
	return frames
}

func TestIOStreamAttachWire_FsTransferHandlerMatchesLiteralGolden(t *testing.T) {
	// Given
	originalClient, originalConfig := client, agentConfig
	t.Cleanup(func() {
		client = originalClient
		agentConfig = originalConfig
	})
	stream := &iostreamWireStream{}
	client = &iostreamWireClient{stream: stream}
	agentConfig = model.AgentConfig{}
	task := &pb.Task{Data: `{"stream_id":"stream-7","op":"invalid","path":"/tmp/x"}`}
	want := []byte{0xff, 0x05, 0xff, 0x05, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x2d, 0x37}

	// When
	handleFsTransferTask(task)

	// Then
	frames := stream.frames()
	if len(frames) < 1 || !bytes.Equal(frames[0], want) {
		t.Fatalf("IOStream attach changed: got %x want %x", frames, want)
	}
}

func TestMCPTransferWire_FiveFrameLayoutsMatchLiteralGoldens(t *testing.T) {
	// Given
	stream := &iostreamWireStream{}
	hashBytes := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}

	// When
	if err := sendXferFixedHeader(stream, model.MCPFsXferMagicUploadHdr, 0x0102030405060708, nil); err != nil {
		t.Fatalf("send upload header: %v", err)
	}
	if err := sendXferFixedHeader(stream, model.MCPFsXferMagicDownloadHdr, 3, hashBytes); err != nil {
		t.Fatalf("send download header: %v", err)
	}
	sender := &grpcXferSender{stream: stream}
	if err := sender.sendXferData([]byte{0xaa, 0xbb, 0xcc}); err != nil {
		t.Fatalf("send chunk: %v", err)
	}
	if err := sendXferOK(stream, hex.EncodeToString(hashBytes), 3); err != nil {
		t.Fatalf("send completion: %v", err)
	}
	sendXferErr(stream, "bad")

	// Then
	wants := [][]byte{
		{0x4e, 0x5a, 0x54, 0x55, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		{0x4e, 0x5a, 0x54, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		{0x4e, 0x5a, 0x54, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xaa, 0xbb, 0xcc},
		{0x4e, 0x5a, 0x54, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		{0x4e, 0x5a, 0x54, 0x45, 0x62, 0x61, 0x64},
	}
	frames := stream.frames()
	if len(frames) != len(wants) {
		t.Fatalf("MCP frame count changed: got %d want %d", len(frames), len(wants))
	}
	for i := range wants {
		if !bytes.Equal(frames[i], wants[i]) {
			t.Fatalf("MCP frame %d changed: got %x want %x", i, frames[i], wants[i])
		}
	}
}

func TestMCPTransferWire_ExactCapAndMutationsAreDetected(t *testing.T) {
	// Given
	if model.MCPFsTransferMaxSize != 104857600 {
		t.Fatalf("MCP transfer cap changed: got %d want 104857600", model.MCPFsTransferMaxSize)
	}
	exactCapStream := &iostreamWireStream{}
	exactCapRequest := &model.FsTransferRequest{Path: filepath.Join(t.TempDir(), "exact-cap.bin"), Size: 104857600}
	oversizeStream := &iostreamWireStream{}
	oversizeRequest := &model.FsTransferRequest{Path: filepath.Join(t.TempDir(), "oversize.bin"), Size: 104857601}
	completionStream := &iostreamWireStream{}
	hashBytes := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	exactHeaderGolden := []byte{0x4e, 0x5a, 0x54, 0x55, 0x00, 0x00, 0x00, 0x00, 0x06, 0x40, 0x00, 0x00}
	oversizeGolden := []byte{0x4e, 0x5a, 0x54, 0x45, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6f, 0x75, 0x74, 0x20, 0x6f, 0x66, 0x20, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x3a, 0x20, 0x6d, 0x75, 0x73, 0x74, 0x20, 0x62, 0x65, 0x20, 0x30, 0x2e, 0x2e, 0x31, 0x30, 0x30, 0x4d, 0x69, 0x42}
	completionGolden := []byte{0x4e, 0x5a, 0x54, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	// When
	fsTransferUpload(exactCapStream, exactCapRequest)
	fsTransferUpload(oversizeStream, oversizeRequest)
	if err := sendXferOK(completionStream, hex.EncodeToString(hashBytes), 3); err != nil {
		t.Fatalf("send completion: %v", err)
	}

	// Then
	exactCapFrames := exactCapStream.frames()
	if len(exactCapFrames) < 1 || !bytes.Equal(exactCapFrames[0], exactHeaderGolden) {
		t.Fatalf("exact 100MiB boundary must enter upload protocol with literal NZTU: got %x", exactCapFrames)
	}
	oversizeFrames := oversizeStream.frames()
	if len(oversizeFrames) != 1 || !bytes.Equal(oversizeFrames[0], oversizeGolden) {
		t.Fatalf("cap+1 must produce exact NZTE rejection: got %x", oversizeFrames)
	}
	completionFrames := completionStream.frames()
	if len(completionFrames) != 1 || !bytes.Equal(completionFrames[0], completionGolden) {
		t.Fatalf("completion frame changed: got %x", completionFrames)
	}
	assertWireMutationDetected(t, "one byte magic", exactCapFrames[0], exactHeaderGolden, func(frame []byte) []byte { frame[0] = 0x4f; return frame })
	assertWireMutationDetected(t, "short header", exactCapFrames[0], exactHeaderGolden, func(frame []byte) []byte { return frame[:len(frame)-1] })
	assertWireMutationDetected(t, "little endian size", exactCapFrames[0], exactHeaderGolden, func(frame []byte) []byte {
		copy(frame[4:], []byte{0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 0x00, 0x00})
		return frame
	})
	assertWireMutationDetected(t, "completion marker", completionFrames[0], completionGolden, func(frame []byte) []byte { frame[3] = 0x50; return frame })
}
