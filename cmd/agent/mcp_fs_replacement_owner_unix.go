//go:build !windows

package main

import (
	"os"
	"syscall"
)

// keepReplacedFileOwner 让临时文件沿用被替换文件的属主。agent 通常以 root
// 运行，不处理的话覆盖写会把业务账号的文件悄悄变成 root 所有。
// 非特权进程无法 chown 到其他用户，此时保持临时文件现有属主即可，所以忽略错误。
// 必须在 Chmod 之前调用：chown 会清除 setuid/setgid 位。
func keepReplacedFileOwner(replacement *os.File, replaced os.FileInfo) {
	if replaced == nil {
		return
	}
	stat, ok := replaced.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = replacement.Chown(int(stat.Uid), int(stat.Gid))
}
