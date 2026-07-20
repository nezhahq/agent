//go:build unix

package hostfs

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openNativeDirectory(path string) (*os.File, error) {
	var descriptor int
	var err error
	for {
		descriptor, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		return nil, errors.Join(unix.EBADF, unix.Close(descriptor))
	}
	return file, nil
}
