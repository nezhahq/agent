//go:build unix && !aix

package fm

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func openDownloadFile(path string) (downloadFile, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open download file: %w", err)
	}
	closeFD := true
	defer func() {
		if closeFD {
			_ = unix.Close(fd)
		}
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("classify download file: %w", err)
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFREG {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil {
			return nil, fmt.Errorf("read download file flags: %w", err)
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, flags&^unix.O_NONBLOCK); err != nil {
			return nil, fmt.Errorf("restore blocking download file: %w", err)
		}
	}

	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		return nil, fmt.Errorf("wrap download file descriptor: %s", path)
	}
	closeFD = false
	return file, nil
}
