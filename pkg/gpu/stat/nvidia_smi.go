package stat

// Modified from https://github.com/influxdata/telegraf/blob/master/plugins/inputs/nvidia_smi/nvidia_smi.go
// Original License: MIT

import (
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type NvidiaSMI struct {
	BinPath string
}

func (smi *NvidiaSMI) Gather() ([]float64, error) {
	data := smi.pollNvidiaSMI()

	return smi.parse(data)
}

func (smi *NvidiaSMI) Start() error {
	if _, err := os.Stat(smi.BinPath); os.IsNotExist(err) {
		binPath, err := exec.LookPath("nvidia-smi")
		if err != nil {
			return errors.New("didn't find the adequate tool to query GPU utilization")
		}
		smi.BinPath = binPath
	}
	return nil
}

func (smi *NvidiaSMI) pollNvidiaSMI() []byte {
	cmd := exec.Command(smi.BinPath,
		"-q",
		"-x",
	)
	gs, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	return gs
}

func (smi *NvidiaSMI) parse(data []byte) ([]float64, error) {
	var s smistat
	var percentage []float64

	err := xml.Unmarshal(data, &s)
	if err != nil {
		return nil, err
	}

	for _, gpu := range s.GPUs {
		gp, _ := parsePercentage(gpu.Utilization.GpuUtil)
		percentage = append(percentage, gp)
	}

	return percentage, nil
}

func parsePercentage(p string) (float64, error) {
	per := strings.ReplaceAll(p, " ", "")

	t := strings.TrimSuffix(per, "%")

	value, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, err
	}

	return value, nil
}

type nGPU struct {
	Utilization struct {
		GpuUtil string `xml:"gpu_util"`
	} `xml:"utilization"`
}
type smistat struct {
	GPUs []nGPU `xml:"gpu"`
}
