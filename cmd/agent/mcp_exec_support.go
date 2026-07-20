package main

import (
	"bytes"
	"os"
	"strings"
)

var mcpExecEnvAllowlist = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "TZ", "TERM",
	"SystemRoot", "windir", "TEMP", "TMP", "PATHEXT", "ComSpec",
	"USERPROFILE", "HOMEDRIVE", "HOMEPATH", "SystemDrive", "ProgramFiles",
}

func mcpExecEnv(extra map[string]string) []string {
	allowed := make(map[string]struct{}, len(mcpExecEnvAllowlist))
	for _, key := range mcpExecEnvAllowlist {
		allowed[key] = struct{}{}
	}
	env := make([]string, 0, len(mcpExecEnvAllowlist)+len(extra))
	for _, entry := range os.Environ() {
		equals := strings.IndexByte(entry, '=')
		if equals <= 0 {
			continue
		}
		if _, ok := allowed[entry[:equals]]; ok {
			env = append(env, entry)
		}
	}
	for key, value := range extra {
		env = append(env, key+"="+value)
	}
	return env
}

type truncatingBuffer struct {
	buf  bytes.Buffer
	max  int
	full bool
}

func (buffer *truncatingBuffer) Write(data []byte) (int, error) {
	if buffer.full {
		return len(data), nil
	}
	remaining := buffer.max - buffer.buf.Len()
	if remaining <= 0 {
		buffer.full = true
		return len(data), nil
	}
	if len(data) <= remaining {
		return buffer.buf.Write(data)
	}
	_, _ = buffer.buf.Write(data[:remaining])
	buffer.full = true
	return len(data), nil
}
