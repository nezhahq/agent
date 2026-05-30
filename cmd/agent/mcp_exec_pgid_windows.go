//go:build windows

package main

import "os/exec"

func processGroupID(_ *exec.Cmd) int { return 0 }
