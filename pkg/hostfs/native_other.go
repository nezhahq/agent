//go:build !unix && !windows

package hostfs

import "os"

func openNativeDirectory(string) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}
