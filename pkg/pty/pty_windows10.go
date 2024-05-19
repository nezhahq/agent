//go:build windows && windows10

package pty

import (
	"os"
	"os/exec"
	"path/filepath"

	"github.com/UserExistsError/conpty"
)

type Pty struct {
	tty *conpty.ConPty
}

func DownloadDependency() {
}

func getExecutableFilePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(ex), nil
}

func Start() (*Pty, error) {
	shellPath, err := exec.LookPath("powershell.exe")
	if err != nil || shellPath == "" {
		shellPath = "cmd.exe"
	}
	path, err := getExecutableFilePath()
	if err != nil {
		return nil, err
	}
	tty, err := conpty.Start(shellPath, conpty.ConPtyWorkDir(path))
	return &Pty{tty: tty}, err
}

func (pty *Pty) Write(p []byte) (n int, err error) {
	return pty.tty.Write(p)
}

func (pty *Pty) Read(p []byte) (n int, err error) {
	return pty.tty.Read(p)
}

func (pty *Pty) Setsize(cols, rows uint32) error {
	return pty.tty.Resize(int(cols), int(rows))
}

func (pty *Pty) Close() error {
	if err := pty.tty.Close(); err != nil {
		return err
	}
	return nil
}