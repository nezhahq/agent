package util

import (
	"cmp"
	"context"
	"errors"
	"iter"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
)

const MacOSChromeUA = "nezha-agent/1.0"

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

func RemoveDuplicate[S ~[]E, E cmp.Ordered](list S) S {
	if list == nil {
		return nil
	}
	out := make([]E, len(list))
	copy(out, list)
	slices.Sort(out)
	return slices.Compact(out)
}

func RotateQueue1(start, i, size int) int {
	return (start + i) % size
}

func RangeRnd[S ~[]E, E any](s S) iter.Seq2[int, E] {
	index := int(time.Now().Unix()) % len(s)
	return func(yield func(int, E) bool) {
		for i := range len(s) {
			r := RotateQueue1(index, i, len(s))
			if !yield(r, s[r]) {
				break
			}
		}
	}
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
