//go:build unix && !aix

package util

import (
	"syscall"

	"github.com/shirou/gopsutil/v4/process"
)

func killChildProcess(child *process.Process) error {
	pgid, err := syscall.Getpgid(int(child.Pid))
	if err != nil {
		return child.Kill()
	} else {
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
}
