//go:build !windows && !linux

package pty

import "os"

// interruptibleTransferFile 在 Linux 以外直接使用主端本身，见 Linux 版本的说明。
func interruptibleTransferFile(tty *os.File) *os.File {
	return tty
}
