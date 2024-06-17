//go:build freebsd

package stat

func GetGPUStat() (float64, error) {
	return -1, nil
}