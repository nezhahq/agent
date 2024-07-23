//go:build windows && !arm64

package pty

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"

	"github.com/UserExistsError/conpty"
	"github.com/artdarek/go-unzip"
	"github.com/iamacarpet/go-winpty"
	"github.com/shirou/gopsutil/v4/host"
)

var isWin10 bool

type Pty interface {
	Write(p []byte) (n int, err error)
	Read(p []byte) (n int, err error)
	Setsize(cols, rows uint32) error
	Close() error
}

type winPTY struct {
	tty *winpty.WinPTY
}

type conPty struct {
	tty *conpty.ConPty
}

func init() {
	isWin10 = VersionCheck()
}

func VersionCheck() bool {
	hi, err := host.Info()
	if err != nil {
		return false
	}

	re := regexp.MustCompile(`Build (\d+(\.\d+)?)`)
	match := re.FindStringSubmatch(hi.KernelVersion)
	if len(match) > 1 {
		versionStr := match[1]

		version, err := strconv.ParseFloat(versionStr, 64)
		if err != nil {
			return false
		}

		return version >= 17763
	}
	return false
}

func DownloadDependency() {
	if !isWin10 {
		executablePath, err := getExecutableFilePath()
		if err != nil {
			fmt.Println("NEZHA>> wintty 获取文件路径失败", err)
			return
		}

		winptyAgentExe := filepath.Join(executablePath, "winpty-agent.exe")
		winptyAgentDll := filepath.Join(executablePath, "winpty.dll")

		fe, errFe := os.Stat(winptyAgentExe)
		fd, errFd := os.Stat(winptyAgentDll)
		if errFe == nil && fe.Size() > 300000 && errFd == nil && fd.Size() > 300000 {
			return
		}

		resp, err := http.Get("https://github.com/rprichard/winpty/releases/download/0.4.3/winpty-0.4.3-msvc2015.zip")
		if err != nil {
			log.Println("NEZHA>> wintty 下载失败", err)
			return
		}
		defer resp.Body.Close()
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Println("NEZHA>> wintty 下载失败", err)
			return
		}
		if err := os.WriteFile("./wintty.zip", content, os.FileMode(0777)); err != nil {
			log.Println("NEZHA>> wintty 写入失败", err)
			return
		}
		if err := unzip.New("./wintty.zip", "./wintty").Extract(); err != nil {
			fmt.Println("NEZHA>> wintty 解压失败", err)
			return
		}
		arch := "x64"
		if runtime.GOARCH != "amd64" {
			arch = "ia32"
		}

		os.Rename("./wintty/"+arch+"/bin/winpty-agent.exe", winptyAgentExe)
		os.Rename("./wintty/"+arch+"/bin/winpty.dll", winptyAgentDll)
		os.RemoveAll("./wintty")
		os.RemoveAll("./wintty.zip")
	}
}

func getExecutableFilePath() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(ex), nil
}

func Start() (Pty, error) {
	shellPath, err := exec.LookPath("powershell.exe")
	if err != nil || shellPath == "" {
		shellPath = "cmd.exe"
	}
	path, err := getExecutableFilePath()
	if err != nil {
		return nil, err
	}
	if !isWin10 {
		tty, err := winpty.OpenDefault(path, shellPath)
		return &winPTY{tty: tty}, err
	}
	tty, err := conpty.Start(shellPath, conpty.ConPtyWorkDir(path))
	return &conPty{tty: tty}, err
}

func (w *winPTY) Write(p []byte) (n int, err error) {
	return w.tty.StdIn.Write(p)
}

func (w *winPTY) Read(p []byte) (n int, err error) {
	return w.tty.StdOut.Read(p)
}

func (w *winPTY) Setsize(cols, rows uint32) error {
	w.tty.SetSize(cols, rows)
	return nil
}

func (w *winPTY) Close() error {
	w.tty.Close()
	return nil
}

func (c *conPty) Write(p []byte) (n int, err error) {
	return c.tty.Write(p)
}

func (c *conPty) Read(p []byte) (n int, err error) {
	return c.tty.Read(p)
}

func (c *conPty) Setsize(cols, rows uint32) error {
	c.tty.Resize(int(cols), int(rows))
	return nil
}

func (c *conPty) Close() error {
	if err := c.tty.Close(); err != nil {
		return err
	}
	return nil
}
