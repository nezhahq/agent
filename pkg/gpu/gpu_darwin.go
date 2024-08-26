//go:build darwin

package gpu

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

type (
	CFStringEncoding = uint32
	CFIndex          = int32
	CFTypeID         = int32
	CFNumberType     = CFIndex
	CFTypeRef        = unsafe.Pointer
	CFStringRef      = unsafe.Pointer
	CFDictionaryRef  = unsafe.Pointer

	machPort        = uint32
	ioIterator      = uint32
	ioObject        = uint32
	ioRegistryEntry = uint32
	ioService       = uint32
	IOOptionBits    = uint32
)

type (
	CFStringCreateWithCStringFunc = func(alloc uintptr, cStr string, encoding CFStringEncoding) CFStringRef
	CFGetTypeIDFunc               = func(cf uintptr) CFTypeID
	CFStringGetTypeIDFunc         = func() CFTypeID
	CFStringGetCStringFunc        = func(cfStr uintptr, buffer *byte, size CFIndex, encoding CFStringEncoding) bool
	CFDictionaryGetTypeIDFunc     = func() CFTypeID
	CFDictionaryGetValueFunc      = func(dict, key uintptr) unsafe.Pointer
	CFNumberGetValueFunc          = func(number uintptr, theType CFNumberType, valuePtr uintptr) bool
	CFReleaseFunc                 = func(cf uintptr)

	IOServiceGetMatchingServicesFunc    = func(mainPort machPort, matching uintptr, existing *ioIterator) ioService
	IOIteratorNextFunc                  = func(iterator ioIterator) ioObject
	IOServiceMatchingFunc               = func(name string) CFDictionaryRef
	IORegistryEntrySearchCFPropertyFunc = func(entry ioRegistryEntry, plane string, key, allocator uintptr, options IOOptionBits) CFTypeRef
	IOObjectReleaseFunc                 = func(object ioObject) int
)

const (
	KERN_SUCCESS   = 0
	MACH_PORT_NULL = 0
	IOSERVICE_GPU  = "IOAccelerator"
	IOSERVICE_PCI  = "IOPCIDevice"

	kIOServicePlane               = "IOService"
	kIORegistryIterateRecursively = 1
	kCFStringEncodingUTF8         = 0x08000100
	kCFNumberIntType              = 9
)

var (
	kCFAllocatorDefault uintptr  = 0
	kIOMainPortDefault  machPort = 0
)

var (
	coreFoundation, _ = purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	ioKit, _          = purego.Dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_LAZY|purego.RTLD_GLOBAL)

	cfStringCreateWithCString, _ = purego.Dlsym(coreFoundation, "CFStringCreateWithCString")
	cfGetTypeID, _               = purego.Dlsym(coreFoundation, "CFGetTypeID")
	cfStringGetTypeID, _         = purego.Dlsym(coreFoundation, "CFStringGetTypeID")
	cfStringGetCString, _        = purego.Dlsym(coreFoundation, "CFStringGetCString")
	cfDictionaryGetTypeID, _     = purego.Dlsym(coreFoundation, "CFDictionaryGetTypeID")
	cfDictionaryGetValue, _      = purego.Dlsym(coreFoundation, "CFDictionaryGetValue")
	cfNumberGetValue, _          = purego.Dlsym(coreFoundation, "CFNumberGetValue")
	cfRelease, _                 = purego.Dlsym(coreFoundation, "CFRelease")

	ioServiceGetMatchingServices, _    = purego.Dlsym(ioKit, "IOServiceGetMatchingServices")
	ioIteratorNext, _                  = purego.Dlsym(ioKit, "IOIteratorNext")
	ioServiceMatching, _               = purego.Dlsym(ioKit, "IOServiceMatching")
	ioRegistryEntrySearchCFProperty, _ = purego.Dlsym(ioKit, "IORegistryEntrySearchCFProperty")
	ioObjectRelease, _                 = purego.Dlsym(ioKit, "IOObjectRelease")
)

var (
	CFStringCreateWithCString CFStringCreateWithCStringFunc
	CFGetTypeID               CFGetTypeIDFunc
	CFStringGetTypeID         CFStringGetTypeIDFunc
	CFStringGetCString        CFStringGetCStringFunc
	CFDictionaryGetTypeID     CFDictionaryGetTypeIDFunc
	CFDictionaryGetValue      CFDictionaryGetValueFunc
	CFNumberGetValue          CFNumberGetValueFunc
	CFRelease                 CFReleaseFunc

	IOServiceGetMatchingServices    IOServiceGetMatchingServicesFunc
	IOIteratorNext                  IOIteratorNextFunc
	IOServiceMatching               IOServiceMatchingFunc
	IORegistryEntrySearchCFProperty IORegistryEntrySearchCFPropertyFunc
	IOObjectRelease                 IOObjectReleaseFunc
)

func init() {
	purego.RegisterFunc(&CFStringCreateWithCString, cfStringCreateWithCString)
	purego.RegisterFunc(&CFGetTypeID, cfGetTypeID)
	purego.RegisterFunc(&CFStringGetTypeID, cfStringGetTypeID)
	purego.RegisterFunc(&CFStringGetCString, cfStringGetCString)
	purego.RegisterFunc(&CFDictionaryGetTypeID, cfDictionaryGetTypeID)
	purego.RegisterFunc(&CFDictionaryGetValue, cfDictionaryGetValue)
	purego.RegisterFunc(&CFNumberGetValue, cfNumberGetValue)
	purego.RegisterFunc(&CFRelease, cfRelease)

	purego.RegisterFunc(&IOServiceGetMatchingServices, ioServiceGetMatchingServices)
	purego.RegisterFunc(&IOIteratorNext, ioIteratorNext)
	purego.RegisterFunc(&IOServiceMatching, ioServiceMatching)
	purego.RegisterFunc(&IORegistryEntrySearchCFProperty, ioRegistryEntrySearchCFProperty)
	purego.RegisterFunc(&IOObjectRelease, ioObjectRelease)
}

func GetGPUModel() ([]string, error) {
	return findDevices("model")
}

func FindUtilization(key, dictKey string) (int, error) {
	return findUtilization(key, dictKey)
}

func findDevices(key string) ([]string, error) {
	var iterator ioIterator
	var results []string

	iv := IOServiceGetMatchingServices(kIOMainPortDefault, uintptr(IOServiceMatching(IOSERVICE_GPU)), &iterator)
	if iv != KERN_SUCCESS {
		return nil, fmt.Errorf("error retrieving GPU entry")
	}

	var service ioObject
	index := 0

	for {
		service = IOIteratorNext(iterator)
		if service == MACH_PORT_NULL {
			break
		}

		cfStr := CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8)
		result, _, _ := findProperties(service, uintptr(cfStr), 0)
		IOObjectRelease(service)

		if result != nil {
			results = append(results, string(result))
			index++
		} else if key == "model" {
			IOObjectRelease(iterator)
			iv = IOServiceGetMatchingServices(kIOMainPortDefault, uintptr(IOServiceMatching(IOSERVICE_PCI)), &iterator)
			if iv != KERN_SUCCESS {
				return nil, fmt.Errorf("error retrieving GPU entry")
			}
		}
	}

	IOObjectRelease(iterator)
	return results, nil
}

func findUtilization(key, dictKey string) (int, error) {
	var iterator ioIterator
	var result int
	var err error

	iv := IOServiceGetMatchingServices(kIOMainPortDefault, uintptr(IOServiceMatching(IOSERVICE_GPU)), &iterator)
	if iv != KERN_SUCCESS {
		return 0, fmt.Errorf("error retrieving GPU entry")
	}

	// Only retrieving the utilization of first GPU here
	service := IOIteratorNext(iterator)
	if service != MACH_PORT_NULL {
		cfStr := CFStringCreateWithCString(kCFAllocatorDefault, key, CFStringEncoding(kCFStringEncodingUTF8))
		cfDictStr := CFStringCreateWithCString(kCFAllocatorDefault, dictKey, CFStringEncoding(kCFStringEncodingUTF8))

		_, result, err = findProperties(service, uintptr(cfStr), uintptr(cfDictStr))

		CFRelease(uintptr(cfStr))
		CFRelease(uintptr(cfDictStr))

		if err != nil {
			return 0, fmt.Errorf("failed retrieving GPU utilization: %v", err)
		}
	} else {
		IOObjectRelease(service)
		IOObjectRelease(iterator)
		return 0, fmt.Errorf("no GPU utilization entry found")
	}

	IOObjectRelease(service)
	IOObjectRelease(iterator)
	return result, nil
}

func findProperties(service ioRegistryEntry, key, dictKey uintptr) ([]byte, int, error) {
	properties := IORegistryEntrySearchCFProperty(service, kIOServicePlane, key, kCFAllocatorDefault, kIORegistryIterateRecursively)
	ptrValue := uintptr(properties)
	if properties != nil {
		switch CFGetTypeID(ptrValue) {
		// model
		case CFStringGetTypeID():
			buf := make([]byte, 1024)
			CFStringGetCString(ptrValue, &buf[0], int32(unsafe.Sizeof(buf)), uint32(kCFStringEncodingUTF8))
			CFRelease(ptrValue)
			return buf, 0, nil
		// PerformanceStatistics
		case CFDictionaryGetTypeID():
			cfValue := CFDictionaryGetValue(ptrValue, dictKey)
			if cfValue != nil {
				var value int
				if CFNumberGetValue(uintptr(cfValue), kCFNumberIntType, uintptr(unsafe.Pointer(&value))) {
					return nil, value, nil
				} else {
					return nil, 0, fmt.Errorf("failed to exec CFNumberGetValue")
				}
			} else {
				return nil, 0, fmt.Errorf("failed to exec CFDictionaryGetValue")
			}
		}
	}
	return nil, 0, fmt.Errorf("failed to exec IORegistryEntrySearchCFProperty")
}
