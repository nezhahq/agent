//go:build unix

package hostfs

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const finalOpenDeadline = 2 * time.Second

func TestAnchoredClassify_identifies_unix_special_files(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	fifoPath := filepath.Join(root, "fifo")
	socketPath := filepath.Join(root, "socket")
	symlinkPath := filepath.Join(root, "symlink")
	regularPath := filepath.Join(root, "regular")
	if err := os.WriteFile(regularPath, []byte("regular"), 0o600); err != nil {
		t.Fatalf("create regular file: %v", err)
	}
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("create Unix socket: %v", err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close Unix socket: %v", err)
		}
	})
	if err := os.Symlink(regularPath, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	tests := []struct {
		name string
		path string
		want FinalTargetType
	}{
		{name: "FIFO", path: fifoPath, want: FinalTargetFIFO},
		{name: "socket", path: socketPath, want: FinalTargetSocket},
		{name: "symlink", path: symlinkPath, want: FinalTargetSymlinkReparse},
		{name: "device", path: "/dev/null", want: FinalTargetDeviceOther},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor := newTestAnchor(t, test.path)

			got, err := anchor.ClassifyFinal()

			if err != nil {
				t.Fatalf("ClassifyFinal(): %v", err)
			}
			if got != test.want {
				t.Fatalf("ClassifyFinal() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestAnchoredRejectsFinal_special_targets_boundedly(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	regularPath := filepath.Join(root, "regular")
	fifoPath := filepath.Join(root, "fifo")
	socketPath := filepath.Join(root, "socket")
	symlinkPath := filepath.Join(root, "symlink")
	if err := os.WriteFile(regularPath, []byte("regular"), 0o600); err != nil {
		t.Fatalf("create regular file: %v", err)
	}
	if err := unix.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("create Unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Symlink(regularPath, symlinkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	tests := []struct {
		name string
		path string
		want FinalTargetType
	}{
		{name: "FIFO", path: fifoPath, want: FinalTargetFIFO},
		{name: "socket", path: socketPath, want: FinalTargetSocket},
		{name: "symlink", path: symlinkPath, want: FinalTargetSymlinkReparse},
		{name: "device", path: "/dev/null", want: FinalTargetDeviceOther},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			anchor := newTestAnchor(t, test.path)
			result := make(chan error, 1)

			go func() {
				file, openErr := anchor.OpenRegular()
				if file != nil {
					_ = file.Close()
				}
				result <- openErr
			}()

			select {
			case openErr := <-result:
				assertFinalTargetTypeError(t, openErr, FinalTargetRegular, test.want)
			case <-time.After(finalOpenDeadline):
				t.Fatalf("OpenRegular(%s) exceeded %s", test.name, finalOpenDeadline)
			}
		})
	}
}
