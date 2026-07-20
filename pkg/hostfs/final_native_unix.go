//go:build unix

package hostfs

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func openFinalNative(request finalOpenRequest) (result finalOpenResult, resultErr error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if request.intent == finalOpenDirectory {
		flags |= unix.O_DIRECTORY
	}
	var descriptor int
	var err error
	for {
		descriptor, err = unix.Openat(int(request.parent.Fd()), request.name, flags, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return finalOpenResult{}, err
	}
	closeDescriptor := true
	defer func() {
		if closeDescriptor {
			resultErr = joinFinalCleanup(resultErr, func() error { return unix.Close(descriptor) })
		}
	}()

	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		return finalOpenResult{}, err
	}
	targetType := finalTargetTypeFromUnixMode(uint32(stat.Mode))
	if request.intent == finalOpenClassify && targetType != FinalTargetRegular && targetType != FinalTargetDirectory {
		return finalOpenResult{targetType: targetType}, nil
	}
	if request.intent == finalOpenRegular && targetType != FinalTargetRegular ||
		request.intent == finalOpenDirectory && targetType != FinalTargetDirectory {
		return finalOpenResult{targetType: targetType}, nil
	}
	if targetType == FinalTargetRegular {
		flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFL, 0)
		if err != nil {
			return finalOpenResult{}, err
		}
		if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_SETFL, flags&^unix.O_NONBLOCK); err != nil {
			return finalOpenResult{}, err
		}
	}
	file := os.NewFile(uintptr(descriptor), request.name)
	if file == nil {
		return finalOpenResult{}, errors.New("hostfs: could not wrap final target descriptor")
	}
	closeDescriptor = false
	return finalOpenResult{file: file, targetType: targetType}, nil
}

func finalTargetTypeFromUnixMode(mode uint32) FinalTargetType {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return FinalTargetRegular
	case unix.S_IFDIR:
		return FinalTargetDirectory
	case unix.S_IFLNK:
		return FinalTargetSymlinkReparse
	case unix.S_IFIFO:
		return FinalTargetFIFO
	case unix.S_IFSOCK:
		return FinalTargetSocket
	default:
		return FinalTargetDeviceOther
	}
}

func finalTypeCanRejectFromMetadata(targetType FinalTargetType) bool {
	return targetType == FinalTargetSymlinkReparse || targetType == FinalTargetSocket
}
