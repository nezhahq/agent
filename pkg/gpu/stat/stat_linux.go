//go:build linux

package stat

func getNvidiaStat() (float64, error) {
	smi := &NvidiaSMI{
		BinPath:   "/usr/bin/nvidia-smi",
		ExtraInfo: false,
	}
	err := smi.Start()
	if err != nil {
		return 0, err
	}
	data, err := smi.Gather()
	if err != nil {
		return 0, err
	}
	return data.(float64), nil
}

func getAMDStat() (float64, error) {
	rsmi := &ROCmSMI{
		BinPath: "/opt/rocm/bin/rocm-smi",
	}
	err1 := rsmi.Start()
	if err1 != nil {
		return 0, err1
	}
	data, err2 := rsmi.Gather()
	if err2 != nil {
		return 0, err2
	}
	return data, nil
}

func GetGPUStat() (float64, error) {
	gs, err := getNvidiaStat()
	if err != nil {
		gs, err = getAMDStat()
	}
	if err != nil {
		return 0, err
	}
	return gs, nil
}
