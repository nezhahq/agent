package main

import (
	"os"
	"runtime"
)

// fsyncDir flushes the directory entry list to stable storage. On POSIX a
// crash between os.Rename and the next sync may lose the new directory
// entry even though the temp file data was already fsynced — the visible
// effect is the rename "vanishes" on reboot. Calling fsyncDir(parent)
// after a rename closes that window.
//
// On Windows the equivalent guarantee is provided by the FlushFileBuffers
// call we already make on the data file (NTFS flushes the parent on file
// flush), so this is a deliberate no-op there.
func fsyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
