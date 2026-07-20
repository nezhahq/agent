//go:build unix

package hostfs

import "os"

func syncCreatedParentDirectory(directory *os.File) error {
	return directory.Sync()
}

func syncReplacementDirectory(directory *os.File) error {
	return directory.Sync()
}
