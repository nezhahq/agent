package main

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/nezhahq/agent/model"
)

// xferSender / capturingXferSender 是给 streamFileChunks 用的最小写出接口：
// agent 真实路径下由 pb.NezhaService_IOStreamClient.Send 实现；单测里我们
// 只需要捕获写出的帧顺序，不必伪造整条 gRPC 流。
type capturingXferSender struct {
	frames [][]byte
}

func (c *capturingXferSender) sendXferData(p []byte) error {
	c.frames = append(c.frames, append([]byte(nil), p...))
	return nil
}

func (c *capturingXferSender) sendXferErrFrame(msg string) {
	buf := append([]byte(nil), model.MCPFsXferMagicErr...)
	buf = append(buf, []byte(msg)...)
	c.frames = append(c.frames, buf)
}

// streamFileChunks 必须在源文件提前 EOF（被并发截断、文件被替换、磁盘故障）
// 时显式发出 NZTE 错误帧并退出，而不是把 io.EOF / io.ErrUnexpectedEOF 当成
// “正常结束”继续循环。当前实现忽略这两个 errno 且不减少 remaining，会陷
// 入忙等：dashboard 永远等不到 hdr.Size 字节，HTTP 客户端只能等 5min 整条
// IOStream 兜底超时。
func TestStreamFileChunks_SendsErrorFrameOnShortRead(t *testing.T) {
	short := bytes.NewReader([]byte("hello"))
	// 声明 size 比实际 reader 大，模拟“stat 时是 1KiB，真读到一半 EOF”。
	declaredSize := int64(1024)
	sender := &capturingXferSender{}

	err := streamFileChunks(sender, short, declaredSize)
	if err == nil {
		t.Fatalf("streamFileChunks must return an error when reader yields fewer bytes than declaredSize")
	}
	if !(errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) ||
		err.Error() != "" && bytes.Contains([]byte(err.Error()), []byte("truncat"))) {
		// 接受 io.ErrUnexpectedEOF / io.EOF / 含 "truncat" 三种合理实现。
		t.Fatalf("error must be short-read related, got: %v", err)
	}
	// 必须至少发出一个 NZTE 错误帧，dashboard 才能立刻报错而不是等总超时。
	sawErrFrame := false
	for _, fr := range sender.frames {
		if len(fr) >= 4 && bytes.Equal(fr[:4], model.MCPFsXferMagicErr) {
			sawErrFrame = true
			break
		}
	}
	if !sawErrFrame {
		t.Fatalf("expected an NZTE error frame to be sent on short read; frames=%v", sender.frames)
	}
}
