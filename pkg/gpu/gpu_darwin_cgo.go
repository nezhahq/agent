//go:build darwin && cgo

package gpu

// #cgo LDFLAGS: -framework IOKit -framework CoreFoundation
// #include "stat/gpu_darwin.h"
import "C"
import (
	"errors"
	"strings"
	"unsafe"
)

func GoStrings(argc C.int, argv **C.char) []string {
	length := int(argc)
	tmpslice := unsafe.Slice(argv, length)
	gostrings := make([]string, length)
	for i, s := range tmpslice {
		gostrings[i] = C.GoString(s)
	}
	return gostrings
}

func extractGPUInfo(key *C.char) ([]string, error) {
	devices := C.find_devices(key)
	if devices != nil {
		defer C.free(unsafe.Pointer(devices))
		length := 0
		for {
			device := *(**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(devices)) + uintptr(length)*unsafe.Sizeof(*devices)))
			if device == nil {
				break
			}
			length++
		}
		gpu := GoStrings(C.int(length), devices)
		return gpu, nil
	}
	return nil, errors.New("cannot find key")
}

func GetGPUModel() ([]string, error) {
	vendorNames := []string{
		"AMD", "Intel", "Nvidia", "Apple",
	}

	key := C.CString("model")
	defer C.free(unsafe.Pointer(key))

	gi, err := extractGPUInfo(key)
	if err != nil {
		return nil, err
	}

	var gpuModel []string
	for _, model := range gi {
		for _, vendor := range vendorNames {
			if strings.Contains(model, vendor) {
				gpuModel = append(gpuModel, model)
				break
			}
		}
	}
	return gpuModel, nil
}
