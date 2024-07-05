//go:build darwin

package stat

import (
	"os/exec"
	"regexp"
	"strconv"
)

func extractGPUStat(cmd *exec.Cmd) ([]float64, error) {
	gs, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`"Device Utilization %"\s*=\s*(\d+)`)
	matches := re.FindAllSubmatch(gs, -1)
	var u []float64
	for _, match := range matches {
		if len(match) > 1 {
			p, _ := strconv.ParseFloat(string(match[1]), 64)
			u = append(u, p)
		}
	}
	return u, nil
}

func GetGPUStat() (float64, error) {
	ioreg := exec.Command("ioreg", "-rd1", "-c", "IOAccelerator")
	gs, err := extractGPUStat(ioreg)
	if err != nil || len(gs) == 0 {
		return 0, err
	}
	return gs[0], nil
}
