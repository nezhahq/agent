package monitor

import (
	"context"
	"runtime"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor/cpu"
	"github.com/nezhahq/agent/pkg/monitor/disk"
)

func GetHost(config *model.AgentConfig) *model.Host {
	var result model.Host

	var cpuType string
	hostInfo, err := hostInfoProbe()
	if err != nil {
		printf("host.Info error: %v", err)
	} else {
		if hostInfo.VirtualizationRole == "guest" {
			cpuType = "Virtual"
			result.Virtualization = hostInfo.VirtualizationSystem
		} else {
			cpuType = "Physical"
		}
		result.Platform = hostInfo.Platform
		result.PlatformVersion = hostInfo.PlatformVersion
		result.Arch = hostInfo.KernelArch
		result.BootTime = hostInfo.BootTime
		metricLock.Lock()
		cachedBootTime = time.Unix(int64(hostInfo.BootTime), 0)
		metricLock.Unlock()
	}

	cpuContext := context.WithValue(context.Background(), cpu.CPUHostKey, cpuType)
	result.CPU = tryHost(cpuContext, CPU, cpuHostProbe)
	if config != nil && config.GPU {
		result.GPU = tryHost(context.Background(), GPU, gpuHostProbe)
	}
	result.DiskTotal = getDiskTotal(config)

	virtualMemory, err := virtualMemoryProbe()
	if err != nil {
		printf("mem.VirtualMemory error: %v", err)
	} else {
		result.MemTotal = virtualMemory.Total
		if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
			result.SwapTotal = virtualMemory.SwapTotal
		}
	}

	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		swapMemory, err := swapMemoryProbe()
		if err != nil {
			printf("mem.SwapMemory error: %v", err)
		} else {
			result.SwapTotal = swapMemory.Total
		}
	}

	result.Version = Version
	return &result
}

func getDiskTotal(config *model.AgentConfig) uint64 {
	var allowlist []string
	if config != nil {
		allowlist = config.HardDrivePartitionAllowlist
	}
	ctx := context.WithValue(context.Background(), disk.DiskKey, allowlist)
	total, _ := diskHostProbe(ctx)
	return total
}
