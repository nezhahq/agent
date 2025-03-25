//go:build windows

package gpu

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/jaypipes/ghw"
	"golang.org/x/sys/windows"
)

const (
	ERROR_SUCCESS  = 0
	PDH_FMT_DOUBLE = 0x00000200
	PDH_MORE_DATA  = 0x800007d2
	PDH_VAILD_DATA = 0x00000000
	PDH_NEW_DATA   = 0x00000001
	PDH_NO_DATA    = 0x800007d5
)

var (
	modPdh = windows.NewLazySystemDLL("pdh.dll")

	pdhOpenQuery                 = modPdh.NewProc("PdhOpenQuery")
	pdhCollectQueryData          = modPdh.NewProc("PdhCollectQueryData")
	pdhGetFormattedCounterArrayW = modPdh.NewProc("PdhGetFormattedCounterArrayW")
	pdhAddEnglishCounterW        = modPdh.NewProc("PdhAddEnglishCounterW")
	pdhCloseQuery                = modPdh.NewProc("PdhCloseQuery")
)

type PDH_FMT_COUNTERVALUE_DOUBLE struct {
	CStatus     uint32
	DoubleValue float64
}

type PDH_FMT_COUNTERVALUE_ITEM_DOUBLE struct {
	SzName   *uint16
	FmtValue PDH_FMT_COUNTERVALUE_DOUBLE
}

func GetHost(_ context.Context) ([]string, error) {
	var gpuModel []string
	gi, err := ghw.GPU(ghw.WithDisableWarnings())
	if err != nil {
		return nil, err
	}

	for _, card := range gi.GraphicsCards {
		if card.DeviceInfo == nil {
			return nil, errors.New("Cannot find device info")
		}
		gpuModel = append(gpuModel, card.DeviceInfo.Product.Name)
	}

	return gpuModel, nil
}

func GetState(_ context.Context) ([]float64, error) {
	counter, err := newWin32PerformanceCounter("gpu_utilization", "\\GPU Engine(*engtype_3D)\\Utilization Percentage")
	if err != nil {
		return nil, err
	}
	defer pdhCloseQuery.Call(uintptr(counter.Query))

	values, err := getValue(8192, counter)
	if err != nil {
		return nil, err
	}
	tot := min(100, sumArray(values))
	return []float64{tot}, nil
}

// https://github.com/influxdata/telegraf/blob/master/plugins/inputs/win_perf_counters/performance_query.go
func getCounterArrayValue(initialBufSize uint32, counter *win32PerformanceCounter) ([]float64, error) {
	for buflen := initialBufSize; buflen <= 100*1024*1024; buflen *= 2 {
		time.Sleep(10 * time.Millisecond) // GPU 查询必须设置间隔，否则数据不准
		s, _, err := pdhCollectQueryData.Call(uintptr(counter.Query))
		if s != 0 && err != nil {
			if s == PDH_NO_DATA {
				return nil, fmt.Errorf("%w: this counter has not data", err)
			}
			return nil, err
		}
		buf := make([]byte, buflen)
		size := buflen
		var itemCount uint32
		r, _, _ := pdhGetFormattedCounterArrayW.Call(uintptr(counter.Counter), PDH_FMT_DOUBLE, uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&itemCount)), uintptr(unsafe.Pointer(&buf[0])))
		if r == ERROR_SUCCESS {
			items := (*[1 << 20]PDH_FMT_COUNTERVALUE_ITEM_DOUBLE)(unsafe.Pointer(&buf[0]))[:itemCount:itemCount]
			values := make([]float64, 0, itemCount)
			for _, item := range items {
				if item.FmtValue.CStatus == PDH_VAILD_DATA || item.FmtValue.CStatus == PDH_NEW_DATA {
					val := item.FmtValue.DoubleValue
					values = append(values, val)
				}
			}
			return values, nil
		}
		if r != PDH_MORE_DATA {
			return nil, fmt.Errorf("pdhGetFormattedCounterArrayW failed with status 0x%X", r)
		}
	}

	return nil, errors.New("buffer limit reached")
}

func createQuery() (windows.Handle, error) {
	var query windows.Handle
	r, _, err := pdhOpenQuery.Call(0, 0, uintptr(unsafe.Pointer(&query)))
	if r != ERROR_SUCCESS {
		return 0, fmt.Errorf("pdhOpenQuery failed with status 0x%X: %v", r, err)
	}
	return query, nil
}

type win32PerformanceCounter struct {
	PostName    string
	CounterName string
	Query       windows.Handle
	Counter     windows.Handle
}

func newWin32PerformanceCounter(postName, counterName string) (*win32PerformanceCounter, error) {
	query, err := createQuery()
	if err != nil {
		return nil, err
	}
	counter := win32PerformanceCounter{
		Query:       query,
		PostName:    postName,
		CounterName: counterName,
	}
	r, _, err := pdhAddEnglishCounterW.Call(
		uintptr(counter.Query),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(counter.CounterName))),
		0,
		uintptr(unsafe.Pointer(&counter.Counter)),
	)
	if r != ERROR_SUCCESS {
		return nil, fmt.Errorf("pdhAddEnglishCounterW failed with status 0x%X: %v", r, err)
	}
	return &counter, nil
}

func getValue(initialBufSize uint32, counter *win32PerformanceCounter) ([]float64, error) {
	s, _, err := pdhCollectQueryData.Call(uintptr(counter.Query))
	if s != 0 && err != nil {
		if s == PDH_NO_DATA {
			return nil, fmt.Errorf("%w: this counter has not data", err)
		}
		return nil, err
	}

	return getCounterArrayValue(initialBufSize, counter)
}

func sumArray(arr []float64) float64 {
	var sum float64
	for _, value := range arr {
		sum += value
	}
	return sum
}
