package hostfs

import (
	"errors"
	"os"
)

func (anchor *Anchor) revalidateAtomicFinal() (FinalTargetType, error) {
	for range maxFinalTargetAttempts {
		metadata, metadataType, err := anchor.lstatFinal("revalidate atomic final")
		if err != nil || metadata == nil {
			return metadataType, err
		}

		opened, openErr := anchor.finalOperations.open(anchor.finalOpenRequest(finalOpenClassify))
		if openErr != nil {
			if errors.Is(openErr, os.ErrNotExist) {
				continue
			}
			_, currentType, currentErr := anchor.lstatFinal("classify atomic final after open failure")
			if currentErr == nil && currentType != metadataType {
				continue
			}
			if currentErr != nil {
				openErr = errors.Join(openErr, currentErr)
			}
			if currentType == metadataType && finalTypeCanRejectFromMetadata(metadataType) {
				return metadataType, nil
			}
			return FinalTargetAbsent, &PathError{Op: "revalidate atomic final", Path: anchor.targetPath, Err: openErr}
		}
		if opened.file == nil {
			return opened.targetType, nil
		}

		openedInfo, statErr := opened.file.Stat()
		closeErr := opened.file.Close()
		if statErr != nil || closeErr != nil {
			return FinalTargetAbsent, &PathError{
				Op:   "revalidate atomic final",
				Path: anchor.targetPath,
				Err:  errors.Join(statErr, closeErr),
			}
		}
		if anchor.finalOperations.sameFile(metadata, openedInfo) {
			return opened.targetType, nil
		}
	}
	return FinalTargetAbsent, &PathError{Op: "revalidate atomic final", Path: anchor.targetPath, Err: ErrFinalTargetChanged}
}
