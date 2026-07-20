//go:build unix && !aix

package fm

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestOpenDownloadFile_FIFOWithoutWriterReturnsClosableHandle(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "open.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}

	// When
	file, err := openDownloadFile(path)

	// Then
	if err != nil {
		t.Fatalf("open FIFO without writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close FIFO handle: %v", err)
	}
}

func TestOpenDownloadFile_RegularFileRestoresBlockingMode(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "regular.bin")
	if err := os.WriteFile(path, []byte("body"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	// When
	handle, err := openDownloadFile(path)
	if err != nil {
		t.Fatalf("open regular file: %v", err)
	}
	defer handle.Close()
	file, ok := handle.(*os.File)
	if !ok {
		t.Fatalf("regular download handle type = %T, want *os.File", handle)
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("read regular file flags: %v", err)
	}

	// Then
	if flags&unix.O_NONBLOCK != 0 {
		t.Fatalf("regular download file flags = %#x, O_NONBLOCK remained set", flags)
	}
}
