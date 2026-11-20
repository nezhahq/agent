//go:build windows

package main

import "os"

// Windows 上新文件从父目录继承 ACL，没有可沿用的 POSIX 属主。
func keepReplacedFileOwner(*os.File, os.FileInfo) {}
