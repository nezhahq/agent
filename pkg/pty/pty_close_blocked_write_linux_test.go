//go:build linux

package pty

import (
	"bytes"
	"testing"
	"time"
)

// The terminal session relies on this: closing the PTY must release a write
// that is blocked because the foreground program does not read its input.
func TestClose_ReleasesAWriteBlockedByAProgramThatDoesNotReadInput(t *testing.T) {
	terminal, err := Start()
	if err != nil {
		t.Skipf("no shell to start a PTY with: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = terminal.Close()
		}
	}()
	go func() {
		buffer := make([]byte, 4096)
		for {
			if _, err := terminal.Read(buffer); err != nil {
				return
			}
		}
	}()
	// Replace the shell, which reads its input, with a program that does not.
	if _, err := terminal.Write([]byte("exec sleep 300\n")); err != nil {
		t.Fatalf("start the program: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	paste := bytes.Repeat([]byte("a line of pasted text\n"), 64*1024)
	writeFinished := make(chan error, 1)
	go func() {
		_, err := terminal.Write(paste)
		writeFinished <- err
	}()
	select {
	case err := <-writeFinished:
		t.Fatalf("test setup: a %d byte paste did not block (err = %v)", len(paste), err)
	case <-time.After(time.Second):
	}

	closed = true
	if err := terminal.Close(); err != nil {
		t.Logf("close: %v", err)
	}

	select {
	case err := <-writeFinished:
		if err == nil {
			t.Fatal("the blocked write reported success after the PTY was closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing the PTY did not release the blocked write")
	}
}
