//go:build linux || windows

package stat

import (
	"runtime"
)

func defaultNvidiaSmiPath() string {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe`
	}

	return "/usr/bin/nvidia-smi"
}

func getNvidiaStatEx() ([]*NGPUInfo, error) {
	smi := &NvidiaSMI{
		BinPath:   defaultNvidiaSmiPath(),
		ExtraInfo: true,
	}
	err := smi.Start()
	if err != nil {
		return nil, err
	}
	data, err := smi.Gather()
	if err != nil {
		return nil, err
	}
	return data.([]*NGPUInfo), nil
}

func GetGPUStatEx() ([]*NGPUInfo, error) {
	/*
		gs, err := getNvidiaStatEx()
		if err != nil {
			return nil, err
		}
		if err != nil {
			return nil, err
		}
	*/
	test1 := &NGPUInfo{
		Model: "NVIDIA GTX 1080",
		Stat: struct {
			Temperature float64
			Usage       float64
		}{
			Temperature: 65.5,
			Usage:       75.0,
		},
	}
	test2 := &NGPUInfo{
		Model: "NVIDIA RTX 2080",
		Stat: struct {
			Temperature float64
			Usage       float64
		}{
			Temperature: 65.9,
			Usage:       11.1,
		},
	}
	gstest := []*NGPUInfo{test1, test2}
	//return gs, nil
	return gstest, nil
}
