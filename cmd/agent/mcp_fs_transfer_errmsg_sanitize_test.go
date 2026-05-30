package main

import (
	"bytes"
	"testing"

	"github.com/nezhahq/agent/model"
)

type pathLeakReader struct{ err error }

func (r *pathLeakReader) Read(p []byte) (int, error) { return 0, r.err }

// streamFileChunks 在非 EOF 读错误时发出的 NZTE 帧必须经过 fsErrMsg 脱敏，
// 不能把含绝对路径的原始 *PathError 文本下发给 dashboard/远端。
func TestStreamFileChunks_SanitizesReadErrorFrame(t *testing.T) {
	secret := "/secret/host/path/file.db"
	raw := &leakyError{msg: "read " + secret + ": input/output error"}
	sender := &capturingXferSender{}

	err := streamFileChunks(sender, &pathLeakReader{err: raw}, 1024)
	if err == nil {
		t.Fatal("streamFileChunks must surface the read error")
	}

	var errFrame []byte
	for _, fr := range sender.frames {
		if len(fr) >= 4 && bytes.Equal(fr[:4], model.MCPFsXferMagicErr) {
			errFrame = fr
		}
	}
	if errFrame == nil {
		t.Fatalf("expected an NZTE error frame; frames=%v", sender.frames)
	}
	if bytes.Contains(errFrame, []byte(secret)) {
		t.Fatalf("error frame leaked host path: %q", errFrame)
	}
	wantMsg := append(append([]byte(nil), model.MCPFsXferMagicErr...), []byte(fsErrMsg(raw))...)
	if !bytes.Equal(errFrame, wantMsg) {
		t.Fatalf("error frame = %q, want sanitized %q", errFrame, wantMsg)
	}
}

type leakyError struct{ msg string }

func (e *leakyError) Error() string { return e.msg }
