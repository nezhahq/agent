package main

import (
	"bytes"
	"testing"
)

type capturingDownloadSender struct {
	frames [][]byte
	errs   []string
}

func (c *capturingDownloadSender) sendXferData(p []byte) error {
	c.frames = append(c.frames, append([]byte(nil), p...))
	return nil
}

func (c *capturingDownloadSender) sendXferErrFrame(msg string) {
	c.errs = append(c.errs, msg)
}

// streamFileChunks 对 declaredSize=0 的契约：不发任何 NZTC chunk、不发 NZTE
// 错误帧、不返回错误。最终的 NZTO 帧由 fsTransferDownload 在 streamFileChunks
// 返回后单独发送，不在本函数职责内。
func TestStreamFileChunks_ZeroByteEmitsNoFramesAndNoError(t *testing.T) {
	sender := &capturingDownloadSender{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("zero-byte streamFileChunks must not panic; got: %v", r)
		}
	}()

	if err := streamFileChunks(sender, bytes.NewReader(nil), 0); err != nil {
		t.Fatalf("streamFileChunks(0) returned unexpected err: %v", err)
	}
	if len(sender.frames) != 0 {
		t.Fatalf("zero-byte transfer must not emit data frames; got %d frames", len(sender.frames))
	}
	if len(sender.errs) != 0 {
		t.Fatalf("zero-byte transfer must not emit NZTE error frames; got %v", sender.errs)
	}
}
