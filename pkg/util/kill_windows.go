//go:build windows

package util

import (
	"errors"
	"os"

	"github.com/shirou/gopsutil/v4/process"
)

func KillProcessByCmd(cmd string) error {
	procs, err := process.Processes()
	if err != nil {
		return err
	}

	var perr error
	for _, proc := range procs {
		pcmd, _ := proc.Exe()
		if pcmd == cmd && proc.Pid != int32(os.Getpid()) {
			if children, err := proc.Children(); err == nil {
				for _, child := range children {
					perr = errors.Join(perr, killChildProcess(child))
				}
			}
			perr = errors.Join(perr, proc.Kill())
		}
	}

	return perr
}

func killChildProcess(child *process.Process) error {
	return child.Kill()
}
