package vendor

// Modified from https://github.com/influxdata/telegraf/blob/master/plugins/inputs/amd_rocm_smi/amd_rocm_smi.go
// Original License: MIT

import (
	"errors"
	"os"
	"os/exec"

	"github.com/tidwall/gjson"
)

type ROCmSMI struct {
	BinPath string
	data    []byte
}

func (rsmi *ROCmSMI) GatherModel() ([]string, error) {
	return rsmi.gatherModel()
}

func (rsmi *ROCmSMI) GatherUsage() ([]float64, error) {
	return rsmi.gatherUsage()
}

func (rsmi *ROCmSMI) Start() error {
	if _, err := os.Stat(rsmi.BinPath); os.IsNotExist(err) {
		binPath, err := exec.LookPath("rocm-smi")
		if err != nil {
			return errors.New("didn't find the adequate tool to query GPU utilization")
		}
		rsmi.BinPath = binPath
	}

	rsmi.data = rsmi.pollROCmSMI()
	return nil
}

func (rsmi *ROCmSMI) pollROCmSMI() []byte {
	cmd := exec.Command(rsmi.BinPath,
		"-u",
		"--showproductname",
		"--json",
	)
	gs, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	return gs
}

func (rsmi *ROCmSMI) gatherModel() ([]string, error) {
	m, err := parseModel(rsmi.data)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (rsmi *ROCmSMI) gatherUsage() ([]float64, error) {
	u, err := parseUsage(rsmi.data)
	if err != nil {
		return nil, err
	}

	return u, nil
}

func parseModel(jsonObject []byte) ([]string, error) {
	if jsonObject == nil {
		return nil, nil
	}

	result := gjson.ParseBytes(jsonObject)
	if !result.IsObject() {
		return nil, errors.New("invalid JSON")
	}

	ret := make([]string, 0)
	result.ForEach(func(_, value gjson.Result) bool {
		ret = append(ret, value.Get("Card series").String())
		return true
	})

	return ret, nil
}

func parseUsage(jsonObject []byte) ([]float64, error) {
	if jsonObject == nil {
		return nil, nil
	}

	result := gjson.ParseBytes(jsonObject)
	if !result.IsObject() {
		return nil, errors.New("invalid JSON")
	}

	ret := make([]float64, 0)
	result.ForEach(func(_, value gjson.Result) bool {
		ret = append(ret, value.Get("GPU use (%)").Float())
		return true
	})

	return ret, nil
}
