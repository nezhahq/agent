package stat

// Modified from https://github.com/influxdata/telegraf/blob/master/plugins/inputs/nvidia_smi/nvidia_smi.go
// Original License: MIT

import (
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type NvidiaSMI struct {
	BinPath   string
	ExtraInfo bool
}

func (smi *NvidiaSMI) Gather() (interface{}, error) {
	data := smi.pollNvidiaSMI()

	return smi.parse(data)
}

func (smi *NvidiaSMI) Start() error {
	if _, err := os.Stat(smi.BinPath); os.IsNotExist(err) {
		binPath, err := exec.LookPath(getSuffix())
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

func (smi *NvidiaSMI) parse(data []byte) (interface{}, error) {
	var s smistat

	err := xml.Unmarshal(data, &s)
	if err != nil {
		return nil, err
	}

	gis := []*NGPUInfo{}

	for _, gpu := range s.GPUs {
		if smi.ExtraInfo {
			gi := &NGPUInfo{Model: gpu.ProductName}
			gp, _ := parsePercentage(gpu.Utilization.GpuUtil)
			gi.Stat.Usage = gp
			gt, _ := parseTemperature(gpu.Temperature.GpuTemp)
			gi.Stat.Temperature = gt
			gis = append(gis, gi)
		} else {
			gp, _ := parsePercentage(gpu.Utilization.GpuUtil)
			return gp, nil
		}
	}

	return gis, nil
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

func parseTemperature(temp string) (float64, error) {
	per := strings.ReplaceAll(temp, " ", "")

	t := strings.TrimSuffix(per, "C")

	value, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, err
	}

	return value, nil
}

func getSuffix() string {
	if runtime.GOOS == "windows" {
		return "nvidia-smi.exe"
	}

	return "nvidia-smi"
}

type nGPU struct {
	Utilization struct {
		GpuUtil string `xml:"gpu_util"`
	} `xml:"utilization"`
	Temperature struct {
		GpuTemp string `xml:"gpu_temp"`
	} `xml:"temperature"`
	ProductName string `xml:"product_name"`
}
type smistat struct {
	GPUs []nGPU `xml:"gpu"`
}

type NGPUInfo struct {
	Model string
	Stat  struct {
		Temperature float64
		Usage       float64
	}
}
