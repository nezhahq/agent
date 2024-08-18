//go:build !windows && !linux

package stat

import "errors"

func GetGPUStatEx() ([]*NGPUInfo, error) {
	return nil, errors.New("extra gpu stats is not available on this platform")
}
