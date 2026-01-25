//go:build linux

package gpu

import (
	"context"
	"errors"

	"github.com/nezhahq/agent/pkg/monitor/gpu/vendor"
)

const (
	vendorAMD = iota + 1
	vendorNVIDIA
	vendorIntel
)

var vendorType = getVendor()

func getVendor() uint8 {
	// Check NVIDIA first (most common discrete GPU)
	_, err := getNvidiaStat()
	if err == nil {
		return vendorNVIDIA
	}

	// Check AMD second
	_, err = getAMDStat()
	if err == nil {
		return vendorAMD
	}

	// Check Intel iGPU last
	_, err = getIntelStat()
	if err == nil {
		return vendorIntel
	}

	// Default fallback - try AMD (original behavior)
	return vendorAMD
}

func getNvidiaStat() ([]float64, error) {
	smi := &vendor.NvidiaSMI{
		BinPath: "/usr/bin/nvidia-smi",
	}
	err1 := smi.Start()
	if err1 != nil {
		return nil, err1
	}
	data, err2 := smi.GatherUsage()
	if err2 != nil {
		return nil, err2
	}
	return data, nil
}

func getAMDStat() ([]float64, error) {
	rsmi := &vendor.ROCmSMI{
		BinPath: "/opt/rocm/bin/rocm-smi",
	}
	err := rsmi.Start()
	if err != nil {
		return nil, err
	}
	data, err := rsmi.GatherUsage()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getIntelStat() ([]float64, error) {
	igt := &vendor.IntelGPUTop{
		BinPath: "/usr/bin/intel_gpu_top",
	}
	err := igt.Start()
	if err != nil {
		return nil, err
	}
	data, err := igt.GatherUsage()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getNvidiaHost() ([]string, error) {
	smi := &vendor.NvidiaSMI{
		BinPath: "/usr/bin/nvidia-smi",
	}
	err := smi.Start()
	if err != nil {
		return nil, err
	}
	data, err := smi.GatherModel()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getAMDHost() ([]string, error) {
	rsmi := &vendor.ROCmSMI{
		BinPath: "/opt/rocm/bin/rocm-smi",
	}
	err := rsmi.Start()
	if err != nil {
		return nil, err
	}
	data, err := rsmi.GatherModel()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getIntelHost() ([]string, error) {
	igt := &vendor.IntelGPUTop{
		BinPath: "/usr/bin/intel_gpu_top",
	}
	err := igt.Start()
	if err != nil {
		return nil, err
	}
	data, err := igt.GatherModel()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func GetHost(_ context.Context) ([]string, error) {
	var gi []string
	var err error

	switch vendorType {
	case vendorAMD:
		gi, err = getAMDHost()
	case vendorNVIDIA:
		gi, err = getNvidiaHost()
	case vendorIntel:
		gi, err = getIntelHost()
	default:
		return nil, errors.New("invalid vendor")
	}

	if err != nil {
		return nil, err
	}

	return gi, nil
}

func GetState(_ context.Context) ([]float64, error) {
	var gs []float64
	var err error

	switch vendorType {
	case vendorAMD:
		gs, err = getAMDStat()
	case vendorNVIDIA:
		gs, err = getNvidiaStat()
	case vendorIntel:
		gs, err = getIntelStat()
	default:
		return nil, errors.New("invalid vendor")
	}

	if err != nil {
		return nil, err
	}

	return gs, nil
}
