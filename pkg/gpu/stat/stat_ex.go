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
	gs, err := getNvidiaStatEx()
	if err != nil {
		return nil, err
	}
	return gs, nil
}
