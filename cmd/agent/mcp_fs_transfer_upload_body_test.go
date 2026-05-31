package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// errRecvCalledPastBody is returned by a fake recv that must never be invoked
// once the declared body has been fully received. The honest dashboard sends
// no terminator after the body — it waits to READ the agent's OK — so any
// post-body Recv() deadlocks both sides. This sentinel turns an over-read into
// a deterministic test failure, guarding against a future naive "read one more
// frame to detect trailing data" change that would hang production.
var errRecvCalledPastBody = errors.New("recv called after body fully received")

func framesRecv(t *testing.T, frames [][]byte) func() ([]byte, error) {
	t.Helper()
	i := 0
	return func() ([]byte, error) {
		if i >= len(frames) {
			return nil, errRecvCalledPastBody
		}
		f := frames[i]
		i++
		return f, nil
	}
}

func TestReceiveUploadBody_AcceptsSingleFrameExactFill(t *testing.T) {
	recv := framesRecv(t, [][]byte{[]byte("abcd")})
	var sink bytes.Buffer
	h := sha256.New()

	n, err := receiveUploadBody(recv, &sink, h, 4)
	if err != nil {
		t.Fatalf("exact fill must pass, got %v", err)
	}
	if n != 4 || sink.String() != "abcd" {
		t.Fatalf("body must be written verbatim, got n=%d %q", n, sink.String())
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha256Hex("abcd") {
		t.Fatalf("hash must cover the body, got %s", got)
	}
}

func TestReceiveUploadBody_AcceptsMultiFrameExactFill(t *testing.T) {
	recv := framesRecv(t, [][]byte{[]byte("ab"), []byte("cd")})
	var sink bytes.Buffer
	h := sha256.New()

	n, err := receiveUploadBody(recv, &sink, h, 4)
	if err != nil {
		t.Fatalf("multi-frame exact fill must pass, got %v", err)
	}
	if n != 4 || sink.String() != "abcd" {
		t.Fatalf("body must be written verbatim, got n=%d %q", n, sink.String())
	}
}

func TestReceiveUploadBody_SkipsEmptyKeepaliveFrames(t *testing.T) {
	recv := framesRecv(t, [][]byte{{}, []byte("ab"), {}, []byte("cd")})
	var sink bytes.Buffer
	h := sha256.New()

	n, err := receiveUploadBody(recv, &sink, h, 4)
	if err != nil {
		t.Fatalf("keep-alive frames must be skipped, got %v", err)
	}
	if n != 4 || sink.String() != "abcd" {
		t.Fatalf("body must be written verbatim, got n=%d %q", n, sink.String())
	}
}

func TestReceiveUploadBody_RejectsSingleFrameOversend(t *testing.T) {
	recv := framesRecv(t, [][]byte{[]byte("0123456789")})
	var sink bytes.Buffer
	h := sha256.New()

	_, err := receiveUploadBody(recv, &sink, h, 4)
	if err == nil {
		t.Fatal("a frame larger than declared size must be rejected")
	}
	if !strings.Contains(err.Error(), "oversend") {
		t.Fatalf("error must mention oversend, got %v", err)
	}
}

func TestReceiveUploadBody_RejectsLastFrameThatCrossesBoundary(t *testing.T) {
	recv := framesRecv(t, [][]byte{[]byte("ab"), []byte("cde")})
	var sink bytes.Buffer
	h := sha256.New()

	_, err := receiveUploadBody(recv, &sink, h, 4)
	if err == nil {
		t.Fatal("final frame crossing the size boundary must be rejected as oversend")
	}
	if !strings.Contains(err.Error(), "oversend") {
		t.Fatalf("error must mention oversend, got %v", err)
	}
}

func TestReceiveUploadBody_PropagatesRecvErrorBeforeFill(t *testing.T) {
	sentinel := errors.New("transport reset")
	recv := func() ([]byte, error) { return nil, sentinel }
	var sink bytes.Buffer
	h := sha256.New()

	_, err := receiveUploadBody(recv, &sink, h, 4)
	if !errors.Is(err, sentinel) {
		t.Fatalf("recv error before fill must propagate, got %v", err)
	}
}

// The honest path never over-reads: once size bytes arrive, receiveUploadBody
// must return WITHOUT calling recv again. framesRecv returns
// errRecvCalledPastBody on an extra call, so an over-read surfaces as this
// error instead of a deadlock.
func TestReceiveUploadBody_DoesNotReadPastDeclaredSize(t *testing.T) {
	recv := framesRecv(t, [][]byte{[]byte("abcd")})
	var sink bytes.Buffer
	h := sha256.New()

	if _, err := receiveUploadBody(recv, &sink, h, 4); err != nil {
		t.Fatalf("exact fill must pass without reading past the body, got %v", err)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
