package stat

// Modified from https://github.com/influxdata/telegraf/blob/master/plugins/inputs/amd_rocm_smi/amd_rocm_smi.go
// Original License: MIT

import (
	"errors"
	"os"
	"os/exec"
	"strconv"

	"github.com/nezhahq/agent/pkg/util"
)

type ROCmSMI struct {
	BinPath string
}

func (rsmi *ROCmSMI) Gather() (float64, error) {
	data := rsmi.pollROCmSMI()

	return gatherROCmSMI(data)
}

func (rsmi *ROCmSMI) Start() error {
	if _, err := os.Stat(rsmi.BinPath); os.IsNotExist(err) {
		binPath, err := exec.LookPath("rocm-smi")
		if err != nil {
			return errors.New("Didn't find the adequate tool to query GPU utilization")
		}
		rsmi.BinPath = binPath
	}
	return nil
}

func (rsmi *ROCmSMI) pollROCmSMI() []byte {
	cmd := exec.Command(rsmi.BinPath,
		"-u",
		"--json",
	)
	gs, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	return gs
}

func gatherROCmSMI(ret []byte) (float64, error) {
	var gpus map[string]GPU
	var gp float64

	err := util.Json.Unmarshal(ret, &gpus)
	if err != nil {
		return 0, err
	}

	for _, gpu := range gpus {
		gp, _ = strconv.ParseFloat(gpu.GpuUsePercentage, 64)
		break
	}

	return gp, nil
}

type GPU struct {
	GpuUsePercentage string `json:"GPU use (%)"`
}
