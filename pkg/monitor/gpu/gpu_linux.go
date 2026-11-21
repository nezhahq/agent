//go:build linux

package gpu

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/nezhahq/agent/pkg/monitor/gpu/vendor"
)

const (
	vendorAMD = iota + 1
	vendorNVIDIA
	vendorIntel
)

// 厂商探测要运行 nvidia-smi / rocm-smi，必须推迟到第一次真正采集 GPU 时再做。
// 以前放在包初始化里：驱动异常、工具卡死的机器上，agent 启动甚至只是执行 -v
// 都要先等满工具超时，即使配置里根本没开 GPU 监控。
var (
	detectVendorOnce sync.Once
	detectedVendor   uint8
	probeVendor      = getVendor
	// vendorProbeRuns 只供测试确认“包加载时没有探测”：没有 GPU 的机器上探测结果
	// 本来就是 0，看 detectedVendor 分辨不出探测有没有跑过。
	vendorProbeRuns atomic.Int32
)

func vendorType() uint8 {
	detectVendorOnce.Do(func() {
		vendorProbeRuns.Add(1)
		detectedVendor = probeVendor()
	})
	return detectedVendor
}

func getVendor() uint8 {
	// Check NVIDIA first (most common discrete GPU)
	// Use Start() which is lightweight for NVIDIA (just checks binary exists)
	smi := &vendor.NvidiaSMI{BinPath: "/usr/bin/nvidia-smi"}
	if smi.Start() == nil {
		return vendorNVIDIA
	}

	// Check AMD second
	rsmi := &vendor.ROCmSMI{BinPath: "/opt/rocm/bin/rocm-smi"}
	if rsmi.Start() == nil {
		return vendorAMD
	}

	// Check Intel iGPU last - use lightweight detection (no process spawning)
	igt := &vendor.IntelGPUTop{BinPath: "/usr/bin/intel_gpu_top"}
	if igt.IsAvailable() {
		return vendorIntel
	}

	// Default fallback - no GPU detected
	return 0
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

	switch vendorType() {
	case vendorAMD:
		gi, err = getAMDHost()
	case vendorNVIDIA:
		gi, err = getNvidiaHost()
	case vendorIntel:
		gi, err = getIntelHost()
	default:
		return nil, nil // No GPU detected
	}

	if err != nil {
		return nil, err
	}

	return gi, nil
}

func GetState(_ context.Context) ([]float64, error) {
	var gs []float64
	var err error

	switch vendorType() {
	case vendorAMD:
		gs, err = getAMDStat()
	case vendorNVIDIA:
		gs, err = getNvidiaStat()
	case vendorIntel:
		gs, err = getIntelStat()
	default:
		return nil, nil // No GPU detected
	}

	if err != nil {
		return nil, err
	}

	return gs, nil
}
