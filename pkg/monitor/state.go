package monitor

import (
	"context"
	"math"
	"runtime"
	"slices"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor/disk"
)

func GetState(config *model.AgentConfig, skipConnectionCount bool, skipProcsCount bool) *model.HostState {
	var result model.HostState

	cpuState := tryStat(context.Background(), CPU, cpuStateProbe)
	if len(cpuState) > 0 {
		result.CPU = cpuState[0]
	}

	virtualMemory, err := virtualMemoryProbe()
	if err != nil {
		printf("mem.VirtualMemory error: %v", err)
	} else {
		if virtualMemory.Used > math.MaxInt64 && runtime.GOOS == "linux" {
			result.MemUsed = virtualMemory.Total - virtualMemory.Free
		} else {
			result.MemUsed = virtualMemory.Used
		}
		if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
			result.SwapUsed = virtualMemory.SwapTotal - virtualMemory.SwapFree
		}
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		swapMemory, err := swapMemoryProbe()
		if err != nil {
			printf("mem.SwapMemory error: %v", err)
		} else {
			result.SwapUsed = swapMemory.Used
		}
	}

	result.DiskUsed = getDiskUsed(config)
	loadState := tryStat(context.Background(), Load, loadStateProbe)
	result.Load1 = loadState.Load1
	result.Load5 = loadState.Load5
	result.Load15 = loadState.Load15

	if !skipProcsCount {
		processIDs, err := processIDsProbe()
		if err != nil {
			printf("process.Pids error: %v", err)
		} else {
			result.ProcessCount = uint64(len(processIDs))
		}
	}

	if config != nil && config.Temperature {
		go updateTemperatureStat()
		temperatureLock.RLock()
		result.Temperatures = slices.Clone(temperatureStat)
		temperatureLock.RUnlock()
	}
	if config != nil && config.GPU {
		result.GPU = tryStat(context.Background(), GPU, gpuStateProbe)
	}

	metricLock.RLock()
	result.NetInTransfer, result.NetOutTransfer = netInTransfer, netOutTransfer
	result.NetInSpeed, result.NetOutSpeed = netInSpeed, netOutSpeed
	result.Uptime = uint64(time.Since(cachedBootTime).Seconds())
	metricLock.RUnlock()
	if !skipConnectionCount {
		result.TcpConnCount, result.UdpConnCount = getConns()
	}
	return &result
}

func getDiskUsed(config *model.AgentConfig) uint64 {
	var allowlist []string
	if config != nil {
		allowlist = config.HardDrivePartitionAllowlist
	}
	ctx := context.WithValue(context.Background(), disk.DiskKey, allowlist)
	used, _ := diskStateProbe(ctx)
	return used
}

func getConns() (tcpConnCount, udpConnCount uint64) {
	connectionState, err := connStateProbe(context.Background())
	if err != nil || len(connectionState) < 2 {
		return 0, 0
	}
	return connectionState[0], connectionState[1]
}

func updateTemperatureStat() {
	if !updateTempStatus.CompareAndSwap(false, true) {
		return
	}
	defer func() {
		updateTempStatus.Store(false)
		temperatureUpdated()
	}()

	stat := tryStat(context.Background(), Temperatures, temperatureProbe)
	temperatureLock.Lock()
	temperatureStat = stat
	temperatureLock.Unlock()
}
