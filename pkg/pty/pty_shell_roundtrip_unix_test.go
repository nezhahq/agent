//go:build unix && !aix

package pty

import (
	"bytes"
	"testing"
	"time"
)

// The transfer handle must still be an ordinary terminal: what the shell
// prints comes back, and closing ends a read that is waiting for output.
func TestStart_InputReachesTheShellAndItsOutputComesBack(t *testing.T) {
	terminal, err := Start()
	if err != nil {
		t.Skipf("no shell to start a PTY with: %v", err)
	}
	output := make(chan []byte, 64)
	readFinished := make(chan struct{})
	go func() {
		defer close(readFinished)
		buffer := make([]byte, 4096)
		for {
			read, err := terminal.Read(buffer)
			if read > 0 {
				output <- append([]byte(nil), buffer[:read]...)
			}
			if err != nil {
				return
			}
		}
	}()
	if _, err := terminal.Write([]byte("echo pty-$((40+2))-roundtrip\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var seen []byte
	deadline := time.After(10 * time.Second)
	for !bytes.Contains(seen, []byte("pty-42-roundtrip")) {
		select {
		case chunk := <-output:
			seen = append(seen, chunk...)
		case <-deadline:
			_ = terminal.Close()
			t.Fatalf("the shell's output never came back; got %q", seen)
		}
	}
	if err := terminal.Setsize(100, 30); err != nil {
		t.Errorf("Setsize: %v", err)
	}

	_ = terminal.Close()

	select {
	case <-readFinished:
	case <-time.After(5 * time.Second):
		t.Fatal("closing the PTY did not end the waiting read")
	}
}
