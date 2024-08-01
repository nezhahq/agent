//go:build !windows && !linux

package stat

func GetGPUStatEx() ([]*NGPUInfo, error) {
	return nil, nil
}
