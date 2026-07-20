//go:build !unix && !windows

package hostfs

import "os"

func openNativeChildDirectory(*os.File, string) (*os.File, error) {
	return nil, ErrUnsupportedPlatform
}
