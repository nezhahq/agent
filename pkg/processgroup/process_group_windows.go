//go:build windows

package processgroup

import (
	"os/exec"
	"sync"
	"syscall"
	"unsafe"
)

type ProcessExitGroup struct {
	cmds []*exec.Cmd
}

func NewProcessExitGroup() (ProcessExitGroup, error) {
	return ProcessExitGroup{}, nil
}

func (g *ProcessExitGroup) Dispose() []error {
	var wg sync.WaitGroup
	wg.Add(len(g.cmds))
	errChan := make(chan error, len(g.cmds))
	for _, c := range g.cmds {
		go func(c *exec.Cmd) {
			defer wg.Done()
			if err := killChildProcess(c.Process.Pid); err != nil {
				errChan <- err
			}
		}(c)
	}

	wg.Wait()
	close(errChan)

	errors := make([]error, 0, len(errChan))
	for err := range errChan {
		errors = append(errors, err)
	}
	return errors
}

func (g *ProcessExitGroup) AddProcess(cmd *exec.Cmd) error {
	g.cmds = append(g.cmds, cmd)
	return nil
}

func killChildProcess(pid int) error {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, uint32(0))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(snap)

	var pe syscall.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := syscall.Process32First(snap, &pe); err != nil {
		return err
	}

	// kill child processes first
	for {
		if pe.ParentProcessID == uint32(pid) {
			child, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, pe.ProcessID)
			if err == nil {
				syscall.TerminateProcess(child, 1)
				syscall.CloseHandle(child)
			}
		}

		if err = syscall.Process32Next(snap, &pe); err != nil {
			break
		}
	}

	proc, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE|syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(proc)

	// kill the main process
	syscall.TerminateProcess(proc, 1)
	_, err = syscall.WaitForSingleObject(proc, syscall.INFINITE)

	return err
}
