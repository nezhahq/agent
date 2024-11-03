package vendor

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
	data    []byte
}

func (smi *NvidiaSMI) GatherModel() ([]string, error) {
	return smi.gatherModel()
}

func (smi *NvidiaSMI) GatherUsage() ([]float64, error) {
	return smi.gatherUsage()
}

func (smi *NvidiaSMI) Start() error {
	if _, err := os.Stat(smi.BinPath); os.IsNotExist(err) {
		binPath, err := exec.LookPath("nvidia-smi")
		if err != nil {
			return errors.New("didn't find the adequate tool to query GPU utilization")
		}
		smi.BinPath = binPath
	}
	smi.data = smi.pollNvidiaSMI()
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

func (smi *NvidiaSMI) gatherModel() ([]string, error) {
	var s smistat
	var models []string

	err := xml.Unmarshal(smi.data, &s)
	if err != nil {
		return nil, err
	}

	for _, gpu := range s.GPUs {
		models = append(models, gpu.ProductName)
	}

	return models, nil
}

func (smi *NvidiaSMI) gatherUsage() ([]float64, error) {
	var s smistat
	var percentage []float64

	err := xml.Unmarshal(smi.data, &s)
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

type gpu struct {
	ProductName string `xml:"product_name"`
	Utilization struct {
		GpuUtil string `xml:"gpu_util"`
	} `xml:"utilization"`
}
type smistat struct {
	GPUs []gpu `xml:"gpu"`
}
