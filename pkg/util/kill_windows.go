//go:build windows

package util

import "github.com/shirou/gopsutil/v4/process"

func killChildProcess(child *process.Process) error {
	return child.Kill()
}
