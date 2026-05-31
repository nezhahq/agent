//go:build (!unix && !windows) || aix

package main

import "os"

// openRegularNoFollow falls back to a plain open on exotic platforms that have
// neither O_NOFOLLOW (unix) nor the Windows reparse-point open flag.
func openRegularNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

// openDirNoFollow falls back to a plain open on exotic platforms lacking
// O_DIRECTORY/O_NOFOLLOW/O_NONBLOCK.
func openDirNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}
