//go:build linux

package stat

func getNvidiaStat() ([]float64, error) {
	smi := &NvidiaSMI{
		BinPath: "/usr/bin/nvidia-smi",
	}
	err1 := smi.Start()
	if err1 != nil {
		return nil, err1
	}
	data, err2 := smi.Gather()
	if err2 != nil {
		return nil, err2
	}
	return data, nil
}

func getAMDStat() ([]float64, error) {
	rsmi := &ROCmSMI{
		BinPath: "/opt/rocm/bin/rocm-smi",
	}
	err1 := rsmi.Start()
	if err1 != nil {
		return nil, err1
	}
	data, err2 := rsmi.Gather()
	if err2 != nil {
		return nil, err2
	}
	return data, nil
}

func GetGPUStat() (float64, error) {
	gs, err := getNvidiaStat()
	if err != nil {
		gs, err = getAMDStat()
	}
	if err != nil || len(gs) == 0 {
		return 0, err
	}
	return gs[0], nil
}
