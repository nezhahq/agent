//go:build unix && !aix

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

func NewCommand(arg string) *exec.Cmd {
	cmd := exec.Command("sh", "-c", arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func (g *ProcessExitGroup) Dispose() error {
	var wg sync.WaitGroup
	wg.Add(len(g.cmds))

	for _, c := range g.cmds {
		go func(c *exec.Cmd) {
			defer wg.Done()
			killChildProcess(c)
		}(c)
	}

	wg.Wait()
	return nil
}

func (g *ProcessExitGroup) AddProcess(cmd *exec.Cmd) error {
	g.cmds = append(g.cmds, cmd)
	return nil
}

func killChildProcess(c *exec.Cmd) {
	pgid, err := syscall.Getpgid(c.Process.Pid)
	if err != nil {
		// Fall-back on error. Kill the main process only.
		c.Process.Kill()
	} else {
		// Kill the whole process group.
		syscall.Kill(-pgid, syscall.SIGTERM)
	}
	c.Wait()
}
