//go:build !windows

package processgroup

import (
	"os/exec"
	"sync"
	"syscall"
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
			if err := killChildProcess(c); err != nil {
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	g.cmds = append(g.cmds, cmd)
	return nil
}

func killChildProcess(c *exec.Cmd) error {
	pgid, err := syscall.Getpgid(c.Process.Pid)
	if err != nil {
		// Fall-back on error. Kill the main process only.
		c.Process.Kill()
	}
	// Kill the whole process group.
	syscall.Kill(-pgid, syscall.SIGTERM)
	return c.Wait()
}
