//go:build darwin && cgo

package stat

// #cgo LDFLAGS: -framework IOKit -framework CoreFoundation
// #include "gpu_darwin.h"
import "C"
import (
	"unsafe"
)

func extractGPUStat(key *C.char, dict_key *C.char) (int, error) {
	utilization := C.find_utilization(key, dict_key)
	return int(utilization), nil
}

func GetGPUStat() (float64, error) {
	key := C.CString("PerformanceStatistics")
	dict_key := C.CString("Device Utilization %")
	defer C.free(unsafe.Pointer(key))
	defer C.free(unsafe.Pointer(dict_key))

	gs, _ := extractGPUStat(key, dict_key)
	return float64(gs), nil
}
