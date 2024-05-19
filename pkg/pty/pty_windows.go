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
	"github.com/shirou/gopsutil/v3/host"
)

var isWin10 bool

type Pty struct {
	tty interface{}
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
	match := re.FindStringSubmatch(hi.PlatformVersion)
	if len(match) > 1 {
		versionStr := match[1]

		version, err := strconv.ParseFloat(versionStr, 64)
		if err != nil {
			return false
		}

		return version >= 17763
	} else {
		return false
	}
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

func Start() (*Pty, error) {
	var tty interface{}

	shellPath, err := exec.LookPath("powershell.exe")
	if err != nil || shellPath == "" {
		shellPath = "cmd.exe"
	}
	path, err := getExecutableFilePath()
	if err != nil {
		return nil, err
	}
	if !isWin10 {
		tty, err = winpty.OpenDefault(path, shellPath)
	} else {
		tty, err = conpty.Start(shellPath, conpty.ConPtyWorkDir(path))
	}
	return &Pty{tty: tty}, err
}

func (pty *Pty) Write(p []byte) (n int, err error) {
	if !isWin10 {
		return pty.tty.(*winpty.WinPTY).StdIn.Write(p)
	} else {
		return pty.tty.(*conpty.ConPty).Write(p)
	}
}

func (pty *Pty) Read(p []byte) (n int, err error) {
	if !isWin10 {
		return pty.tty.(*winpty.WinPTY).StdOut.Read(p)
	} else {
		return pty.tty.(*conpty.ConPty).Read(p)
	}
}

func (pty *Pty) Setsize(cols, rows uint32) error {
	if !isWin10 {
		pty.tty.(*winpty.WinPTY).SetSize(cols, rows)
		return nil
	} else {
		return pty.tty.(*conpty.ConPty).Resize(int(cols), int(rows))
	}
}

func (pty *Pty) Close() error {
	if !isWin10 {
		pty.tty.(*winpty.WinPTY).Close()
		return nil
	} else {
		if err := pty.tty.(*conpty.ConPty).Close(); err != nil {
			return err
		}
		return nil
	}
}
