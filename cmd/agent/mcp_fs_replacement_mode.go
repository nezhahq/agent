package main

import (
	"os"
	"strconv"
)

// resolveReplacementMode 决定 fs.write / fs.transfer 上传落盘时的权限位。
//
// 两条路径都是“写临时文件再 rename 覆盖”，临时文件的权限就是最终权限。
// 调用方没有显式给 mode 时必须沿用被替换文件的权限：固定用 0644 会把
// 0600 的私钥、带口令的配置在一次普通编辑后变成全员可读。
//
// 返回的 replaced 非 nil 表示目标原本是一个普通文件，供 keepReplacedFileOwner
// 继续沿用属主。
func resolveReplacementMode(target, requestedMode string) (mode os.FileMode, replaced os.FileInfo, err error) {
	if info, statErr := os.Lstat(target); statErr == nil && info.Mode().IsRegular() {
		replaced = info
	}
	if requestedMode != "" {
		parsed, parseErr := strconv.ParseUint(requestedMode, 8, 32)
		if parseErr != nil {
			return 0, nil, parseErr
		}
		return os.FileMode(parsed) & os.ModePerm, replaced, nil
	}
	if replaced != nil {
		return replaced.Mode().Perm(), replaced, nil
	}
	return 0o644, nil, nil
}
