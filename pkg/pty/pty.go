//go:build !windows

package pty

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"

	opty "github.com/creack/pty"
)

var _ IPty = (*Pty)(nil)

var defaultShells = []string{"zsh", "fish", "bash", "sh"}

type Pty struct {
	tty *os.File
	cmd *exec.Cmd
}

func DownloadDependency() error {
	return nil
}

func Start() (IPty, error) {
	var shellPath string
	for _, sh := range defaultShells {
		shellPath, _ = exec.LookPath(sh)
		if shellPath != "" {
			break
		}
	}
	if shellPath == "" {
		return nil, errors.New("没有可用终端")
	}
	cmd := exec.Command(shellPath) // #nosec
	cmd.Env = terminalEnvironment(os.Environ())
	tty, err := opty.StartWithSize(cmd, &opty.Winsize{
		Cols: defaultTerminalCols,
		Rows: defaultTerminalRows,
	})
	if err != nil {
		return nil, err
	}
	return &Pty{tty: tty, cmd: cmd}, nil
}

func terminalEnvironment(base []string) []string {
	overrides := map[string]string{
		"TERM":         "xterm-256color",
		"COLORTERM":    "truecolor",
		"TERM_PROGRAM": "Nezha",
	}
	environment := make([]string, 0, len(base)+len(overrides))
	for _, item := range base {
		key, _, found := strings.Cut(item, "=")
		if _, overridden := overrides[key]; found && overridden {
			continue
		}
		environment = append(environment, item)
	}
	for _, key := range []string{"TERM", "COLORTERM", "TERM_PROGRAM"} {
		environment = append(environment, key+"="+overrides[key])
	}
	return environment
}

func (pty *Pty) Write(p []byte) (n int, err error) {
	return pty.tty.Write(p)
}

func (pty *Pty) Read(p []byte) (n int, err error) {
	return pty.tty.Read(p)
}

func (pty *Pty) Getsize() (uint16, uint16, error) {
	ws, err := opty.GetsizeFull(pty.tty)
	if err != nil {
		return 0, 0, err
	}
	return ws.Cols, ws.Rows, nil
}

func (pty *Pty) Setsize(cols, rows uint32) error {
	return opty.Setsize(pty.tty, &opty.Winsize{
		Cols: uint16(cols),
		Rows: uint16(rows),
	})
}

// resolveGroupKillPgid 返回可安全用于 Kill(-pgid) 的进程组 id。
// Getpgid 失败或返回非正值时回 0，表示"不要发组 kill"——绝不能让
// Kill(-0, SIGKILL) 打到调用者自己所在的进程组而把 agent 一起杀掉
// （等价于 processgroup 包里 fix #123 的安全契约）。
func resolveGroupKillPgid(pid int) int {
	pgid, err := syscall.Getpgid(pid)
	if err != nil || pgid <= 0 {
		return 0
	}
	return pgid
}

func (pty *Pty) killChildProcess(c *exec.Cmd) error {
	if pgid := resolveGroupKillPgid(c.Process.Pid); pgid > 0 {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	} else {
		_ = c.Process.Kill()
	}
	return c.Wait()
}

func (pty *Pty) Close() error {
	return errors.Join(pty.tty.Close(), pty.killChildProcess(pty.cmd))
}
