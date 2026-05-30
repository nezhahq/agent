//go:build unix && !aix

package main

import (
	"os"
	"syscall"
)

// openRegularNoFollow opens path with O_NOFOLLOW so the open fails when the
// final component is a symlink. This removes the Lstat->Open TOCTOU: the
// kernel resolves and rejects the symlink atomically with the open, so no
// racing swap of a regular file for a symlink can redirect the read.
func openRegularNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
