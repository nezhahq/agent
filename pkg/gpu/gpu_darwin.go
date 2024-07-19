//go:build darwin && !cgo

package gpu

import (
	"os/exec"
	"regexp"
	"strings"
)

func extractGPUInfo(cmd *exec.Cmd) ([]string, error) {
	gi, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`"model"\s*=\s*["<]?"([^">]+)"[">]?`)
	matches := re.FindAllSubmatch(gi, -1)
	var modelNames []string
	for _, match := range matches {
		if len(match) > 1 {
			modelNames = append(modelNames, string(match[1]))
		}
	}
	return modelNames, nil
}

func GetGPUModel() ([]string, error) {
	vendorNames := []string{
		"AMD", "Intel", "Nvidia", "Apple",
	}

	ioreg := exec.Command("ioreg", "-rd1", "-c", "IOAccelerator")
	gi, err := extractGPUInfo(ioreg)
	if err != nil || len(gi) == 0 {
		ioreg = exec.Command("ioreg", "-rd1", "-c", "IOPCIDevice")
		gi, err = extractGPUInfo(ioreg)
		if err != nil {
			return nil, err
		}
	}

	var gpuModel []string
	for _, model := range gi {
		for _, vendor := range vendorNames {
			if strings.Contains(model, vendor) {
				gpuModel = append(gpuModel, model)
				break
			}
		}
	}
	return gpuModel, nil
}
