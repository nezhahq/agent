//go:build !unix && !windows

package hostfs

func openFinalNative(finalOpenRequest) (finalOpenResult, error) {
	return finalOpenResult{}, ErrUnsupportedPlatform
}

func finalTypeCanRejectFromMetadata(targetType FinalTargetType) bool {
	return targetType == FinalTargetSymlinkReparse || targetType == FinalTargetSocket
}
