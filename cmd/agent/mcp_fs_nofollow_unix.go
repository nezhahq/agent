//go:build unix && !aix

package main

import (
	"errors"
	"os"
	"syscall"
)

// openRegularNoFollow opens path with O_NOFOLLOW so the open fails when the
// final component is a symlink. This removes the Lstat->Open TOCTOU: the
// kernel resolves and rejects the symlink atomically with the open, so no
// racing swap of a regular file for a symlink can redirect the read.
//
// O_NONBLOCK 也是必须的：不带它打开一个没有写端的 FIFO 会一直阻塞。调用方在打开
// 期间持有路径锁，而重连前等这把锁没有期限，一次这样的打开就能让 agent 掉线
// 直到重启。FIFO、套接字和设备在这里直接拒绝，普通文件随后恢复成阻塞读。
func openRegularNoFollow(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Mode()&(os.ModeNamedPipe|os.ModeSocket|os.ModeDevice|os.ModeCharDevice) != 0 {
		_ = file.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: errNotARegularFile}
	}
	if err := syscall.SetNonblock(int(file.Fd()), false); err != nil {
		_ = file.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return file, nil
}

var errNotARegularFile = errors.New("not a regular file")

// openDirNoFollow opens path as a directory without following a final-component
// symlink and without blocking. O_DIRECTORY rejects non-directories, O_NOFOLLOW
// rejects a symlinked final component, and O_NONBLOCK guarantees the open
// returns immediately even if the target was swapped for a FIFO between the
// caller's Lstat dir-check and this open (Lstat->Open TOCTOU / DoS).
func openDirNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
