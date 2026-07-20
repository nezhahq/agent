//go:build !unix && !windows

package hostfs

import (
	"os"
	"runtime"
)

func syncCreatedParentDirectory(*os.File) error {
	return &DirectorySyncUnsupportedError{Platform: runtime.GOOS}
}

func syncReplacementDirectory(*os.File) error {
	return &DirectorySyncUnsupportedError{Platform: runtime.GOOS}
}
