//go:build unix && !aix

package util

import (
	"errors"
	"os"
	"syscall"

	"github.com/shirou/gopsutil/v4/process"
)

func KillProcessByCmd(cmd string) error {
	procs, err := process.Processes()
	if err != nil {
		return err
	}

	var perr error
	for _, proc := range procs {
		pcmd, _ := proc.CmdlineSlice()
		if len(pcmd) > 0 && pcmd[0] == cmd && proc.Pid != int32(os.Getpid()) {
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
	pgid, err := syscall.Getpgid(int(child.Pid))
	if err != nil {
		return child.Kill()
	} else {
		return syscall.Kill(-pgid, syscall.SIGTERM)
	}
}
