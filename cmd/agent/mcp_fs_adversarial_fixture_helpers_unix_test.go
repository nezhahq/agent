//go:build unix && !aix

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

type specialFileFixture struct {
	Root        string
	Directory   string
	RegularFile string
	FIFO        string
	Socket      string
	Symlink     string

	socketDirectory string
	listener        *net.UnixListener
	closeOnce       sync.Once
	closeErr        error
}

func createParentReplacementLink(target string, linkPath string) error {
	return os.Symlink(target, linkPath)
}

func swapParentReplacementLink(target string, linkPath string) error {
	replacementPath := linkPath + ".replacement"
	if err := os.Symlink(target, replacementPath); err != nil {
		return fmt.Errorf("create replacement parent link: %w", err)
	}
	if err := os.Rename(replacementPath, linkPath); err != nil {
		_ = os.Remove(replacementPath)
		return fmt.Errorf("replace parent link: %w", err)
	}
	return nil
}

func newSpecialFileFixture(t *testing.T) *specialFileFixture {
	t.Helper()

	root := t.TempDir()
	socketDirectory, err := os.MkdirTemp("/tmp", "agent-special-file-socket-")
	if err != nil {
		t.Fatalf("create fixture socket directory: %v", err)
	}
	fixture := &specialFileFixture{
		Root:            root,
		Directory:       filepath.Join(root, "directory"),
		RegularFile:     filepath.Join(root, "regular-file"),
		FIFO:            filepath.Join(root, "fifo"),
		Socket:          filepath.Join(socketDirectory, "socket"),
		Symlink:         filepath.Join(root, "file-symlink"),
		socketDirectory: socketDirectory,
	}
	t.Cleanup(func() {
		if err := fixture.Close(); err != nil {
			t.Errorf("close special-file fixture: %v", err)
		}
	})
	if err := os.Mkdir(fixture.Directory, 0o700); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(fixture.RegularFile, []byte("regular"), 0o600); err != nil {
		t.Fatalf("create fixture regular file: %v", err)
	}
	if err := unix.Mkfifo(fixture.FIFO, 0o600); err != nil {
		t.Fatalf("create fixture FIFO: %v", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: fixture.Socket, Net: "unix"})
	if err != nil {
		t.Fatalf("create fixture Unix socket: %v", err)
	}
	fixture.listener = listener
	if err := os.Symlink(fixture.RegularFile, fixture.Symlink); err != nil {
		t.Fatalf("create fixture file symlink: %v", err)
	}
	return fixture
}

func (fixture *specialFileFixture) Close() error {
	fixture.closeOnce.Do(func() {
		var listenerErr error
		if fixture.listener != nil {
			listenerErr = fixture.listener.Close()
		}
		fixture.closeErr = errors.Join(listenerErr, os.RemoveAll(fixture.socketDirectory), os.RemoveAll(fixture.Root))
	})
	return fixture.closeErr
}
