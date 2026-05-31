//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// openRegularNoFollow opens path without following a final symlink or reparse
// point. FILE_FLAG_OPEN_REPARSE_POINT makes CreateFile return the reparse
// point itself instead of its target, so the subsequent reparse-attribute
// check rejects it atomically with the open. This closes the Lstat->Open
// TOCTOU where an attacker swaps a regular file for a symlink between the
// handler's Lstat and this open.
func openRegularNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		windows.CloseHandle(handle)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_CANT_ACCESS_FILE}
	}

	return os.NewFile(uintptr(handle), path), nil
}

// openDirNoFollow opens path as a directory handle without following a final
// reparse point (symlink/junction). FILE_FLAG_BACKUP_SEMANTICS is required to
// obtain a directory handle; FILE_FLAG_OPEN_REPARSE_POINT plus the attribute
// check reject a swapped-in symlink atomically with the open, closing the
// Lstat->Open TOCTOU on the fs.list path.
func openDirNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		windows.CloseHandle(handle)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_CANT_ACCESS_FILE}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(handle)
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_DIRECTORY}
	}

	return os.NewFile(uintptr(handle), path), nil
}
