//go:build !darwin
// +build !darwin

package gpu

import (
	"fmt"

	"github.com/jaypipes/ghw"
)

func GetGPUModel() []string {
	var gpuModel []string
	gi, err := ghw.GPU(ghw.WithDisableWarnings())
	if err != nil {
		fmt.Printf("Error getting GPU info: %v", err)
		return nil
	}

	for _, card := range gi.GraphicsCards {
		if card.DeviceInfo == nil {
			return nil
		}
		gpuModel = append(gpuModel, card.DeviceInfo.Product.Name)
	}

	return gpuModel
}
