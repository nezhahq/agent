package monitor

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/logger"
	"github.com/nezhahq/agent/pkg/monitor/conn"
	"github.com/nezhahq/agent/pkg/monitor/cpu"
	"github.com/nezhahq/agent/pkg/monitor/disk"
	"github.com/nezhahq/agent/pkg/monitor/gpu"
	"github.com/nezhahq/agent/pkg/monitor/load"
	"github.com/nezhahq/agent/pkg/monitor/nic"
	"github.com/nezhahq/agent/pkg/monitor/temperature"
	"github.com/nezhahq/agent/pkg/util"
)

var (
	Version     string
	agentConfig *model.AgentConfig

	printf = logger.DefaultLogger.Printf
)

var (
	netInSpeed, netOutSpeed, netInTransfer, netOutTransfer, lastUpdateNetStats uint64
	cachedBootTime                                                             time.Time
	temperatureStat                                                            []model.SensorTemperature
)

// 获取设备数据的最大尝试次数
const maxDeviceDataFetchAttempts = 3

const (
	CPU = iota + 1
	GPU
	Load
	Temperatures
)

// 获取主机数据的尝试次数，Key 为 Host 的属性名
var hostDataFetchAttempts = map[uint8]uint8{
	CPU: 0,
	GPU: 0,
}

// 获取状态数据的尝试次数，Key 为 HostState 的属性名
var statDataFetchAttempts = map[uint8]uint8{
	CPU:          0,
	GPU:          0,
	Load:         0,
	Temperatures: 0,
}

var (
	updateTempStatus atomic.Bool
	stateLock        sync.Mutex
)

func InitConfig(cfg *model.AgentConfig) {
	agentConfig = cfg
}

// GetHost 获取主机硬件信息
func GetHost() *model.Host {
	var ret model.Host

	var cpuType string
	hi, err := host.Info()
	if err != nil {
		printf("host.Info error: %v", err)
	} else {
		if hi.VirtualizationRole == "guest" {
			cpuType = "Virtual"
			ret.Virtualization = hi.VirtualizationSystem
		} else {
			cpuType = "Physical"
			ret.Virtualization = ""
		}
		ret.Platform = hi.Platform
		ret.PlatformVersion = hi.PlatformVersion
		ret.Arch = hi.KernelArch
		ret.BootTime = hi.BootTime
		cachedBootTime = time.Unix(int64(hi.BootTime), 0)
	}

	ctxCpu := context.WithValue(context.Background(), cpu.CPUHostKey, cpuType)
	ret.CPU = tryHost(ctxCpu, CPU, cpu.GetHost)

	if agentConfig.GPU {
		ret.GPU = tryHost(context.Background(), GPU, gpu.GetHost)
	}

	ret.DiskTotal = getDiskTotal()

	mv, err := mem.VirtualMemory()
	if err != nil {
		printf("mem.VirtualMemory error: %v", err)
	} else {
		ret.MemTotal = mv.Total
		if runtime.GOOS != "windows" {
			ret.SwapTotal = mv.SwapTotal
		}
	}

	if runtime.GOOS == "windows" {
		ms, err := mem.SwapMemory()
		if err != nil {
			printf("mem.SwapMemory error: %v", err)
		} else {
			ret.SwapTotal = ms.Total
		}
	}

	ret.Version = Version

	return &ret
}

func GetState(skipConnectionCount bool, skipProcsCount bool) *model.HostState {
	var ret model.HostState

	cp := tryStat(context.Background(), CPU, cpu.GetState)
	if len(cp) > 0 {
		ret.CPU = cp[0]
	}

	vm, err := mem.VirtualMemory()
	if err != nil {
		printf("mem.VirtualMemory error: %v", err)
	} else {
		ret.MemUsed = vm.Total - vm.Available
		if runtime.GOOS != "windows" {
			ret.SwapUsed = vm.SwapTotal - vm.SwapFree
		}
	}
	if runtime.GOOS == "windows" {
		// gopsutil 在 Windows 下不能正确取 swap
		ms, err := mem.SwapMemory()
		if err != nil {
			printf("mem.SwapMemory error: %v", err)
		} else {
			ret.SwapUsed = ms.Used
		}
	}

	ret.DiskUsed = getDiskUsed()

	loadStat := tryStat(context.Background(), Load, load.GetState)
	ret.Load1 = loadStat.Load1
	ret.Load5 = loadStat.Load5
	ret.Load15 = loadStat.Load15

	var procs []int32
	if !skipProcsCount {
		procs, err = process.Pids()
		if err != nil {
			printf("process.Pids error: %v", err)
		} else {
			ret.ProcessCount = uint64(len(procs))
		}
	}

	if agentConfig.Temperature {
		go updateTemperatureStat()
		ret.Temperatures = temperatureStat
	}

	if agentConfig.GPU {
		ret.GPU = tryStat(context.Background(), GPU, gpu.GetState)
	}

	ret.NetInTransfer, ret.NetOutTransfer = netInTransfer, netOutTransfer
	ret.NetInSpeed, ret.NetOutSpeed = netInSpeed, netOutSpeed
	ret.Uptime = uint64(time.Since(cachedBootTime).Seconds())

	if !skipConnectionCount {
		ret.TcpConnCount, ret.UdpConnCount = getConns()
	}

	return &ret
}

// TrackNetworkSpeed NIC监控，统计流量与速度
func TrackNetworkSpeed() {
	var innerNetInTransfer, innerNetOutTransfer uint64

	ctx := context.WithValue(context.Background(), nic.NICKey, agentConfig.NICAllowlist)
	nc, err := nic.GetState(ctx)
	if err != nil {
		return
	}

	innerNetInTransfer = nc[0]
	innerNetOutTransfer = nc[1]

	now := uint64(time.Now().Unix())
	diff := util.SubUintChecked(now, lastUpdateNetStats)
	if diff > 0 {
		netInSpeed = util.SubUintChecked(innerNetInTransfer, netInTransfer) / diff
		netOutSpeed = util.SubUintChecked(innerNetOutTransfer, netOutTransfer) / diff
	}
	netInTransfer = innerNetInTransfer
	netOutTransfer = innerNetOutTransfer
	lastUpdateNetStats = now
}

func getDiskTotal() uint64 {
	ctx := context.WithValue(context.Background(), disk.DiskKey, agentConfig.HardDrivePartitionAllowlist)
	total, _ := disk.GetHost(ctx)

	return total
}

func getDiskUsed() uint64 {
	ctx := context.WithValue(context.Background(), disk.DiskKey, agentConfig.HardDrivePartitionAllowlist)
	used, _ := disk.GetState(ctx)

	return used
}

func getConns() (tcpConnCount, udpConnCount uint64) {
	connStat, err := conn.GetState(context.Background())
	if err != nil {
		return
	}

	if len(connStat) < 2 {
		return
	}

	return connStat[0], connStat[1]
}

func updateTemperatureStat() {
	if !updateTempStatus.CompareAndSwap(false, true) {
		return
	}
	defer updateTempStatus.Store(false)

	stat := tryStat(context.Background(), Temperatures, temperature.GetState)
	temperatureStat = stat
}

type hostStateFunc[T any] func(context.Context) (T, error)

func tryHost[T any](ctx context.Context, typ uint8, f hostStateFunc[T]) T {
	var val T

	if hostDataFetchAttempts[typ] < maxDeviceDataFetchAttempts {
		v, err := f(ctx)
		if err != nil {
			hostDataFetchAttempts[typ]++
			printf("monitor error: %v, type: %d, attempt: %d", err, typ, hostDataFetchAttempts[typ])
			return val
		} else {
			val = v
			hostDataFetchAttempts[typ] = 0
		}
	}
	return val
}

func tryStat[T any](ctx context.Context, typ uint8, f hostStateFunc[T]) T {
	var val T

	stateLock.Lock()
	defer stateLock.Unlock()

	if statDataFetchAttempts[typ] < maxDeviceDataFetchAttempts {
		v, err := f(ctx)
		if err != nil {
			statDataFetchAttempts[typ]++
			printf("monitor error: %v, type: %d, attempt: %d", err, typ, statDataFetchAttempts[typ])
			return val
		} else {
			val = v
			statDataFetchAttempts[typ] = 0
		}
	}
	return val
}
