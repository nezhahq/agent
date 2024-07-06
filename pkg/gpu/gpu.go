//go:build !darwin
// +build !darwin

package gpu

import (
	"errors"

	"github.com/jaypipes/ghw"
)

func GetGPUModel() ([]string, error) {
	var gpuModel []string
	gi, err := ghw.GPU(ghw.WithDisableWarnings())
	if err != nil {
		return nil, err
	}

	for _, card := range gi.GraphicsCards {
		if card.DeviceInfo == nil {
			return nil, errors.New("Cannot find device info")
		}
		gpuModel = append(gpuModel, card.DeviceInfo.Product.Name)
	}

	return gpuModel, nil
}
