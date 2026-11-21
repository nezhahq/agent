//go:build linux

package pty

import (
	"os"
	"syscall"
)

// interruptibleTransferFile 返回一个读写 PTY 主端用的句柄，关闭它能打断正在阻塞的读写。
//
// 主端本身做不到：创建 PTY 时要对它做 ioctl，取文件描述符的那一刻 Go 就把它切成了
// 阻塞模式，此后的读写是不可打断的系统调用，Close 只能等它们自己返回。前台程序不读
// 标准输入时，一次大段粘贴会把写入永久卡住——连子进程被杀掉也不返回，因为主端还
// 没真正关闭，内核的行缓冲仍是满的——终端会话因此永远收不了尾。
// 这里复制一个描述符并设成非阻塞，交给运行时的轮询器，Close 就能让阻塞的读写立刻返回。
// 只在 Linux 上这样做：其他系统的 PTY 设备不一定能注册进轮询器。
func interruptibleTransferFile(tty *os.File) *os.File {
	duplicate, err := syscall.Dup(int(tty.Fd()))
	if err != nil {
		return tty
	}
	syscall.CloseOnExec(duplicate)
	if err := syscall.SetNonblock(duplicate, true); err != nil {
		_ = syscall.Close(duplicate)
		return tty
	}
	return os.NewFile(uintptr(duplicate), tty.Name())
}
