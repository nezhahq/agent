//go:build windows

package hostfs

import "os"

func syncCreatedParentDirectory(*os.File) error {
	// Windows data-file FlushFileBuffers already flushes the parent directory.
	return nil
}

func syncReplacementDirectory(*os.File) error {
	return &DirectorySyncUnsupportedError{Platform: "windows"}
}
