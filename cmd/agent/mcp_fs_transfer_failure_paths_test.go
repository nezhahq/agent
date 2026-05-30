package main

import (
	"bytes"
	"errors"
	"testing"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

// fakeIOStream 是 pb.NezhaService_IOStreamClient 的最小桩，记录写出的帧顺序，
// 让我们在不真起 gRPC 通道的情况下断言协议行为。
type fakeIOStream struct {
	pb.NezhaService_IOStreamClient
	sent      [][]byte
	sendErr   error
	closed    bool
}

func (f *fakeIOStream) Send(d *pb.IOStreamData) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, append([]byte(nil), d.GetData()...))
	return nil
}

func (f *fakeIOStream) CloseSend() error {
	f.closed = true
	return nil
}

func (f *fakeIOStream) Recv() (*pb.IOStreamData, error) {
	return nil, errors.New("fakeIOStream: Recv not expected in early-error path")
}

func (f *fakeIOStream) Header() (metadata.MD, error) { return metadata.MD{}, nil }
func (f *fakeIOStream) Trailer() metadata.MD         { return metadata.MD{} }

// runFsTransferOnStream 是 handleFsTransferTask 在 attach 完成后的协议核心：
// 早退分支必须发完整一帧 NZTE 后立刻返回；正常分支才能继续走 upload/download。
// 这里钉死“早退即 NZTE”的契约，避免之后误改成静默 return。
func TestRunFsTransferOnStream_EarlyErrorSendsExactlyOneNZTE(t *testing.T) {
	f := &fakeIOStream{}
	req := &model.FsTransferRequest{
		StreamID: "sid-1",
		Op:       model.MCPFsTransferOpUpload,
		Path:     "/tmp/x",
	}

	runFsTransferOnStream(f, "FsTransfer 被 agent DisableCommandExecute 拒绝", req)

	if len(f.sent) != 1 {
		t.Fatalf("early-error path must send exactly one frame (NZTE); got %d frames: %v", len(f.sent), f.sent)
	}
	frame := f.sent[0]
	if len(frame) < 4 || !bytes.Equal(frame[:4], model.MCPFsXferMagicErr) {
		t.Fatalf("early-error frame must start with NZTE magic; got %v", frame)
	}
	msg := string(frame[4:])
	if msg == "" {
		t.Fatal("NZTE payload must include the human-readable reason")
	}
}

func TestRunFsTransferOnStream_BadJSONEarlyErrorCarriesParseHint(t *testing.T) {
	f := &fakeIOStream{}
	// 模拟 decideFsTransferEarlyError 返回 (nil, "解析失败...", false)
	// 之后，调用方决定即使 hasStream=false 也仍然尝试 attach（未来可能这样
	// 改）。runFsTransferOnStream 必须能在 req=nil 时也安全发出 NZTE。
	runFsTransferOnStream(f, "FsTransfer 任务解析失败: bad", nil)
	if len(f.sent) != 1 {
		t.Fatalf("must still send NZTE when req=nil; got %d frames", len(f.sent))
	}
	if !bytes.HasPrefix(f.sent[0], model.MCPFsXferMagicErr) {
		t.Fatalf("frame must be NZTE; got %v", f.sent[0])
	}
}
