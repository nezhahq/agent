package hostfs

import (
	"errors"
	"os"
)

const maxFinalTargetAttempts = 4

type finalOpenIntent uint8

const (
	finalOpenClassify finalOpenIntent = iota
	finalOpenRegular
	finalOpenDirectory
)

type finalOpenRequest struct {
	parent *os.File
	name   string
	intent finalOpenIntent
}

type finalOpenResult struct {
	file       *os.File
	targetType FinalTargetType
}

type finalTargetOperations struct {
	lstat    func(*os.Root, string) (os.FileInfo, error)
	open     func(finalOpenRequest) (finalOpenResult, error)
	sameFile func(os.FileInfo, os.FileInfo) bool
}

func defaultFinalTargetOperations() finalTargetOperations {
	return finalTargetOperations{
		lstat:    (*os.Root).Lstat,
		open:     openFinalNative,
		sameFile: os.SameFile,
	}
}

// FinalTargetType classifies one final directory entry without following it.
type FinalTargetType uint8

const (
	FinalTargetAbsent FinalTargetType = iota
	FinalTargetRegular
	FinalTargetDirectory
	FinalTargetSymlinkReparse
	FinalTargetFIFO
	FinalTargetSocket
	FinalTargetDeviceOther
)

func (targetType FinalTargetType) String() string {
	switch targetType {
	case FinalTargetAbsent:
		return "absent"
	case FinalTargetRegular:
		return "regular"
	case FinalTargetDirectory:
		return "directory"
	case FinalTargetSymlinkReparse:
		return "symlink-reparse"
	case FinalTargetFIFO:
		return "FIFO"
	case FinalTargetSocket:
		return "socket"
	case FinalTargetDeviceOther:
		return "device-other"
	}
	return "unknown"
}

// ClassifyFinal returns the type of the anchored final entry without following it.
func (anchor *Anchor) ClassifyFinal() (FinalTargetType, error) {
	if len(anchor.missingParents) != 0 {
		return FinalTargetAbsent, nil
	}
	for range maxFinalTargetAttempts {
		metadata, targetType, err := anchor.lstatFinal("classify final")
		if err != nil || metadata == nil {
			return targetType, err
		}
		if finalTypeCanRejectFromMetadata(targetType) {
			return targetType, nil
		}
		opened, err := anchor.finalOperations.open(anchor.finalOpenRequest(finalOpenClassify))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			current, classifyErr := anchor.classifyAfterOpenFailure()
			if classifyErr == nil && current != targetType {
				continue
			}
			if classifyErr != nil {
				err = errors.Join(err, classifyErr)
			}
			return FinalTargetAbsent, &PathError{Op: "classify final", Path: anchor.targetPath, Err: err}
		}
		if opened.file == nil {
			return opened.targetType, nil
		}
		openedInfo, statErr := opened.file.Stat()
		closeErr := opened.file.Close()
		if statErr != nil || closeErr != nil {
			return FinalTargetAbsent, &PathError{Op: "classify final", Path: anchor.targetPath, Err: errors.Join(statErr, closeErr)}
		}
		if anchor.finalOperations.sameFile(metadata, openedInfo) {
			return opened.targetType, nil
		}
	}
	return FinalTargetAbsent, &PathError{Op: "classify final", Path: anchor.targetPath, Err: ErrFinalTargetChanged}
}

// OpenRegular opens the anchored final entry only when it is a regular file.
func (anchor *Anchor) OpenRegular() (*os.File, error) {
	return anchor.openFinal(FinalTargetRegular, finalOpenRegular)
}

// OpenDirectory opens the anchored final entry only when it is a directory.
func (anchor *Anchor) OpenDirectory() (*os.File, error) {
	return anchor.openFinal(FinalTargetDirectory, finalOpenDirectory)
}

func (anchor *Anchor) openFinal(expected FinalTargetType, intent finalOpenIntent) (*os.File, error) {
	if len(anchor.missingParents) != 0 {
		return nil, anchor.typeError(expected, FinalTargetAbsent)
	}
	for range maxFinalTargetAttempts {
		metadata, metadataType, err := anchor.lstatFinal("open final")
		if err != nil {
			return nil, err
		}
		if metadataType == FinalTargetAbsent || finalTypeCanRejectFromMetadata(metadataType) {
			return nil, anchor.typeError(expected, metadataType)
		}
		opened, err := anchor.finalOperations.open(anchor.finalOpenRequest(intent))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			current, classifyErr := anchor.classifyAfterOpenFailure()
			if classifyErr == nil && current != expected {
				return nil, anchor.typeError(expected, current)
			}
			if classifyErr != nil {
				err = errors.Join(err, classifyErr)
			}
			return nil, &PathError{Op: "open final", Path: anchor.targetPath, Err: err}
		}
		if opened.file == nil {
			return nil, anchor.typeError(expected, opened.targetType)
		}
		openedInfo, statErr := opened.file.Stat()
		if statErr != nil {
			return nil, errors.Join(&PathError{Op: "stat opened final", Path: anchor.targetPath, Err: statErr}, opened.file.Close())
		}
		if !anchor.finalOperations.sameFile(metadata, openedInfo) {
			if closeErr := opened.file.Close(); closeErr != nil {
				return nil, &PathError{Op: "close changed final", Path: anchor.targetPath, Err: closeErr}
			}
			continue
		}
		return opened.file, nil
	}
	return nil, &PathError{Op: "open final", Path: anchor.targetPath, Err: ErrFinalTargetChanged}
}

func (anchor *Anchor) lstatFinal(operation string) (os.FileInfo, FinalTargetType, error) {
	metadata, err := anchor.finalOperations.lstat(anchor.root, anchor.finalName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, FinalTargetAbsent, nil
	}
	if err != nil {
		return nil, FinalTargetAbsent, &PathError{Op: operation, Path: anchor.targetPath, Err: err}
	}
	return metadata, finalTargetTypeFromMode(metadata.Mode()), nil
}

func (anchor *Anchor) classifyAfterOpenFailure() (FinalTargetType, error) {
	_, targetType, err := anchor.lstatFinal("classify final after open failure")
	return targetType, err
}

func (anchor *Anchor) typeError(expected, actual FinalTargetType) error {
	return &FinalTargetTypeError{Path: anchor.targetPath, Expected: expected, Actual: actual}
}

func (anchor *Anchor) finalOpenRequest(intent finalOpenIntent) finalOpenRequest {
	return finalOpenRequest{
		parent: anchor.nativeDirectory,
		name:   anchor.finalName,
		intent: intent,
	}
}

func finalTargetTypeFromMode(mode os.FileMode) FinalTargetType {
	switch {
	case mode.IsRegular():
		return FinalTargetRegular
	case mode.IsDir():
		return FinalTargetDirectory
	case mode&os.ModeSymlink != 0:
		return FinalTargetSymlinkReparse
	case mode&os.ModeNamedPipe != 0:
		return FinalTargetFIFO
	case mode&os.ModeSocket != 0:
		return FinalTargetSocket
	default:
		return FinalTargetDeviceOther
	}
}
