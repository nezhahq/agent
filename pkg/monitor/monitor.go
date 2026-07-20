package monitor

import (
	"context"
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
)

var (
	Version string
	printf  = logger.Printf
)

var (
	hostInfoProbe      = host.Info
	virtualMemoryProbe = mem.VirtualMemory
	swapMemoryProbe    = mem.SwapMemory
	processIDsProbe    = process.Pids
	cpuHostProbe       = cpu.GetHost
	cpuStateProbe      = cpu.GetState
	diskHostProbe      = disk.GetHost
	diskStateProbe     = disk.GetState
	gpuHostProbe       = gpu.GetHost
	gpuStateProbe      = gpu.GetState
	loadStateProbe     = load.GetState
	nicStateProbe      = nic.GetState
	connStateProbe     = conn.GetState
	temperatureProbe   = temperature.GetState
	temperatureUpdated = func() {}
)

var (
	netInSpeed, netOutSpeed, netInTransfer, netOutTransfer, lastUpdateNetStats uint64
	cachedBootTime                                                             time.Time
	temperatureStat                                                            []model.SensorTemperature
)

const maxDeviceDataFetchAttempts = 3

const (
	CPU = iota + 1
	GPU
	Load
	Temperatures
)

var hostDataFetchAttempts = map[uint8]uint8{
	CPU: 0,
	GPU: 0,
}

var statDataFetchAttempts = map[uint8]uint8{
	CPU:          0,
	GPU:          0,
	Load:         0,
	Temperatures: 0,
}

var (
	updateTempStatus atomic.Bool
	hostLock         sync.Mutex
	stateLock        sync.Mutex
	metricLock       sync.RWMutex
	temperatureLock  sync.RWMutex
)

type hostStateFunc[T any] func(context.Context) (T, error)

func tryHost[T any](ctx context.Context, typ uint8, probe hostStateFunc[T]) T {
	var value T
	hostLock.Lock()
	defer hostLock.Unlock()
	if hostDataFetchAttempts[typ] >= maxDeviceDataFetchAttempts {
		return value
	}

	result, err := probe(ctx)
	if err != nil {
		hostDataFetchAttempts[typ]++
		printf("monitor error: %v, type: %d, attempt: %d", err, typ, hostDataFetchAttempts[typ])
		return value
	}
	hostDataFetchAttempts[typ] = 0
	return result
}

func tryStat[T any](ctx context.Context, typ uint8, probe hostStateFunc[T]) T {
	var value T

	stateLock.Lock()
	defer stateLock.Unlock()
	if statDataFetchAttempts[typ] >= maxDeviceDataFetchAttempts {
		return value
	}

	result, err := probe(ctx)
	if err != nil {
		statDataFetchAttempts[typ]++
		printf("monitor error: %v, type: %d, attempt: %d", err, typ, statDataFetchAttempts[typ])
		return value
	}
	statDataFetchAttempts[typ] = 0
	return result
}
