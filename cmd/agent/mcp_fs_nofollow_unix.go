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

// openDirNoFollow opens path as a directory without following a final-component
// symlink and without blocking. O_DIRECTORY rejects non-directories, O_NOFOLLOW
// rejects a symlinked final component, and O_NONBLOCK guarantees the open
// returns immediately even if the target was swapped for a FIFO between the
// caller's Lstat dir-check and this open (Lstat->Open TOCTOU / DoS).
func openDirNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
