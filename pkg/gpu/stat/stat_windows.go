//go:build windows

package stat

import (
	"os/exec"
	"strconv"
	"strings"
)

func GetGPUStat() (float64, error) {
	shellPath, err := exec.LookPath("powershell.exe")
	if err != nil || shellPath == "" {
		return -1, err
	}
	cmd := exec.Command(
		shellPath,
		"-Command",
		`Write-Output "$([math]::Round((((Get-Counter "\GPU Engine(*engtype_3D)\Utilization Percentage").CounterSamples | where CookedValue).CookedValue | measure -sum).sum,2))"`,
	)
	output, err1 := cmd.CombinedOutput()
	if err1 != nil {
		return -1, err1
	}
	t := strings.TrimSpace(string(output))
	gs, err2 := strconv.ParseFloat(t, 64)
	if err2 != nil {
		return -1, err2
	}
	return gs, nil
}