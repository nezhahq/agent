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
	"sync"
)

var (
	nvidiaSmiPath string
	nvidiaSmiOnce sync.Once
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

// GatherStat reports utilization together with frame buffer usage. Both come
// from the same `nvidia-smi -q -x` output already collected for GatherUsage,
// so this costs no additional invocation.
func (smi *NvidiaSMI) GatherStat() ([]GPUStat, error) {
	var s smistat
	if err := xml.Unmarshal(smi.data, &s); err != nil {
		return nil, err
	}
	stats := make([]GPUStat, 0, len(s.GPUs))
	for _, g := range s.GPUs {
		util, _ := parsePercentage(g.Utilization.GpuUtil)
		used, errUsed := parseMiB(g.FbMemory.Used)
		total, errTotal := parseMiB(g.FbMemory.Total)
		stat := GPUStat{Utilization: util}
		if errUsed == nil && errTotal == nil {
			stat.MemoryUsed, stat.MemoryTotal = used, total
		}
		stats = append(stats, stat)
	}
	return stats, nil
}

// parseMiB turns a "1137 MiB" reading into its numeric value.
func parseMiB(v string) (uint64, error) {
	t := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "MiB"))
	n, err := strconv.ParseFloat(t, 64)
	if err != nil || n < 0 {
		return 0, err
	}
	return uint64(n), nil
}

func (smi *NvidiaSMI) Start() error {
	nvidiaSmiOnce.Do(func() {
		if _, err := os.Stat(smi.BinPath); err == nil {
			nvidiaSmiPath = smi.BinPath
		} else {
			if binPath, err := exec.LookPath("nvidia-smi"); err == nil {
				nvidiaSmiPath = binPath
			}
		}
	})

	if nvidiaSmiPath == "" {
		return errors.New("didn't find the adequate tool to query GPU utilization")
	}

	smi.BinPath = nvidiaSmiPath
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
	FbMemory struct {
		Total string `xml:"total"`
		Used  string `xml:"used"`
	} `xml:"fb_memory_usage"`
}
type smistat struct {
	GPUs []gpu `xml:"gpu"`
}
