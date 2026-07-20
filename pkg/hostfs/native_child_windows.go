//go:build windows

package hostfs

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openNativeChildDirectory(parent *os.File, name string) (result *os.File, resultErr error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(parent.Fd()),
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	var statusBlock windows.IO_STATUS_BLOCK
	var handle windows.Handle
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_GENERIC_READ,
		&attributes,
		&statusBlock,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_FOR_BACKUP_INTENT,
		0,
		0,
	)
	if err != nil {
		return nil, windowsError(err)
	}
	closeHandle := true
	defer func() {
		if closeHandle {
			resultErr = errors.Join(resultErr, windows.CloseHandle(handle))
		}
	}()
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return nil, err
	}
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, windows.ERROR_REPARSE_TAG_MISMATCH
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		return nil, windows.ERROR_INVALID_HANDLE
	}
	closeHandle = false
	return file, nil
}
