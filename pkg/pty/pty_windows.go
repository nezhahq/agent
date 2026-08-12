//go:build windows

package pty

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/UserExistsError/conpty"
)

var _ IPty = (*Pty)(nil)

type Pty struct {
	tty  *conpty.ConPty
	mu   sync.RWMutex
	cols uint32
	rows uint32
}

func getExecutableFilePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(ex), nil
}

func Start() (IPty, error) {
	shellPath, err := exec.LookPath("powershell.exe")
	if err != nil || shellPath == "" {
		shellPath = "cmd.exe"
	}
	path, err := getExecutableFilePath()
	if err != nil {
		return nil, err
	}
	tty, err := conpty.Start(
		shellPath,
		conpty.ConPtyWorkDir(path),
		conpty.ConPtyDimensions(defaultTerminalCols, defaultTerminalRows),
	)
	if err != nil {
		return nil, err
	}
	return &Pty{tty: tty, cols: defaultTerminalCols, rows: defaultTerminalRows}, nil
}

func (pty *Pty) Write(p []byte) (n int, err error) {
	return pty.tty.Write(p)
}

func (pty *Pty) Read(p []byte) (n int, err error) {
	return pty.tty.Read(p)
}

func (pty *Pty) Getsize() (uint16, uint16, error) {
	pty.mu.RLock()
	defer pty.mu.RUnlock()
	return uint16(pty.cols), uint16(pty.rows), nil
}

func (pty *Pty) Setsize(cols, rows uint32) error {
	pty.mu.Lock()
	defer pty.mu.Unlock()
	if err := pty.tty.Resize(int(cols), int(rows)); err != nil {
		return err
	}
	pty.cols, pty.rows = cols, rows
	return nil
}

func (pty *Pty) Close() error {
	if err := pty.tty.Close(); err != nil {
		return err
	}
	return nil
}
