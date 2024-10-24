//go:build !darwin && !linux && !windows

package gpu

func GetGPUModel() ([]string, error) {
	return nil, nil
}

func GetGPUStat() ([]float64, error) {
	return nil, nil
}
