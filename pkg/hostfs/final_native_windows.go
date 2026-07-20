//go:build windows

package hostfs

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openFinalNative(request finalOpenRequest) (result finalOpenResult, resultErr error) {
	objectName, err := windows.NewNTUnicodeString(request.name)
	if err != nil {
		return finalOpenResult{}, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: windows.Handle(request.parent.Fd()),
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_FOR_BACKUP_INTENT)
	switch request.intent {
	case finalOpenClassify:
	case finalOpenRegular:
		options |= windows.FILE_NON_DIRECTORY_FILE
	case finalOpenDirectory:
		options |= windows.FILE_DIRECTORY_FILE
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
		options,
		0,
		0,
	)
	if err != nil {
		return finalOpenResult{}, windowsError(err)
	}
	closeHandle := true
	defer func() {
		if closeHandle {
			resultErr = joinFinalCleanup(resultErr, func() error { return windows.CloseHandle(handle) })
		}
	}()

	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return finalOpenResult{}, err
	}
	targetType := FinalTargetRegular
	if information.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		targetType = FinalTargetSymlinkReparse
	} else if information.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		targetType = FinalTargetDirectory
	} else if fileType, err := windows.GetFileType(handle); err != nil {
		return finalOpenResult{}, err
	} else if fileType != windows.FILE_TYPE_DISK {
		targetType = FinalTargetDeviceOther
	}
	if request.intent == finalOpenClassify && targetType != FinalTargetRegular && targetType != FinalTargetDirectory {
		return finalOpenResult{targetType: targetType}, nil
	}
	if request.intent == finalOpenRegular && targetType != FinalTargetRegular ||
		request.intent == finalOpenDirectory && targetType != FinalTargetDirectory {
		return finalOpenResult{targetType: targetType}, nil
	}
	file := os.NewFile(uintptr(handle), request.name)
	if file == nil {
		return finalOpenResult{}, windows.ERROR_INVALID_HANDLE
	}
	closeHandle = false
	return finalOpenResult{file: file, targetType: targetType}, nil
}

func windowsError(err error) error {
	var status windows.NTStatus
	if errors.As(err, &status) {
		return status.Errno()
	}
	return err
}

func finalTypeCanRejectFromMetadata(targetType FinalTargetType) bool {
	return targetType == FinalTargetSocket
}
