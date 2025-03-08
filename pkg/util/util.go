package util

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/shirou/gopsutil/v4/process"
)

const MacOSChromeUA = "nezha-agent/1.0"

var (
	Json = jsoniter.ConfigCompatibleWithStandardLibrary
)

func IsWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func BrowserHeaders() http.Header {
	return http.Header{
		"Accept":          {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"},
		"Accept-Language": {"en,zh-CN;q=0.9,zh;q=0.8"},
		"User-Agent":      {MacOSChromeUA},
	}
}

func ContainsStr(slice []string, str string) bool {
	if str != "" {
		for _, item := range slice {
			if strings.Contains(str, item) {
				return true
			}
		}
	}
	return false
}

func RemoveDuplicate[T comparable](sliceList []T) []T {
	allKeys := make(map[T]struct{})
	var list []T
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = struct{}{}
			list = append(list, item)
		}
	}
	return list
}

// OnceValue returns a function that invokes f only once and returns the value
// returned by f. The returned function may be called concurrently.
//
// If f panics, the returned function will panic with the same value on every call.
func OnceValue[T any](f func() T) func() T {
	var (
		once   sync.Once
		valid  bool
		p      any
		result T
	)
	g := func() {
		defer func() {
			p = recover()
			if !valid {
				panic(p)
			}
		}()
		result = f()
		f = nil
		valid = true
	}
	return func() T {
		once.Do(g)
		if !valid {
			panic(p)
		}
		return result
	}
}

func RotateQueue1(start, i, size int) int {
	return (start + i) % size
}

// LookupIP looks up host using the local resolver.
// It returns a slice of that host's IPv4 and IPv6 addresses.
func LookupIP(host string) ([]net.IP, error) {
	defaultResolver := net.Resolver{PreferGo: true}
	addrs, err := defaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, ia := range addrs {
		ips[i] = ia.IP
	}
	return ips, nil
}

func FindProcessByCmd(cmd string) []*process.Process {
	procs, err := process.Processes()
	if err != nil {
		return nil
	}

	var agentProcs []*process.Process
	for _, proc := range procs {
		pcmd, _ := proc.Exe()
		if pcmd == cmd && proc.Pid != int32(os.Getpid()) {
			agentProcs = append(agentProcs, proc)
		}
	}

	return agentProcs
}

func KillProcesses(procs []*process.Process) error {
	var perr error

	for _, proc := range procs {
		if children, err := proc.Children(); err == nil {
			for _, child := range children {
				perr = errors.Join(perr, killChildProcess(child))
			}
		}
		perr = errors.Join(perr, proc.Kill())
	}

	return perr
}

func SubUintChecked[T Unsigned](a, b T) T {
	if a < b {
		return 0
	}

	return a - b
}

type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}
