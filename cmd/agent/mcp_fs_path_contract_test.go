package main

import (
	"runtime"
	"testing"
)

// hostAbsolutePaths returns already-clean absolute paths valid on the test's
// GOOS. resolveFsPath gates on filepath.IsAbs, which is platform-specific
// (POSIX paths are not absolute on Windows), so the contract samples must
// match the running OS or the windows CI job fails on otherwise-valid input.
func hostAbsolutePaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Windows\System32\drivers\etc\hosts`,
			`C:\ProgramData\nezha\nezha.log`,
			`C:\Users\alice\notes.md`,
			`D:\scratch`,
		}
	}
	return []string{
		"/etc/hosts",
		"/var/log/nezha.log",
		"/root/.ssh/authorized_keys",
		"/home/alice/notes.md",
		"/tmp/scratch",
	}
}

// sensitiveAbsolutePaths returns GOOS-appropriate "looks sensitive" absolute
// paths used to pin the no-sandbox contract.
func sensitiveAbsolutePaths() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:\Windows\System32\config\SAM`,
			`C:\Windows\Tasks\anything`,
			`C:\Program Files\nezha\agent.exe`,
		}
	}
	return []string{
		"/etc/shadow",
		"/etc/cron.d/anything",
		"/usr/local/bin/agent",
	}
}

// MCP fs.* 工具的路径契约：agent 只校验"绝对路径"且拒绝把整盘当 root 写删，
// 不在 agent 内做 sandbox。理由：dashboard/LLM 给出的是 agent 宿主机上的绝对
// 路径，由 agent 进程的文件系统权限决定能不能动；上层授权（PAT scope / server
// whitelist）已经替每个调用方限定了"能操作哪台 agent"，sandbox 不是这一层的
// 责任。
//
// 这组测试把契约钉死：将来如果有人想加入沙箱（限制只能动某根目录、跟随
// symlink 校验等），这些测试会直接失败，迫使他在 PR 描述里显式声明契约变更。
func TestFsPathContract_AcceptsAnyHostAbsolutePath(t *testing.T) {
	t.Parallel()

	for _, p := range hostAbsolutePaths() {
		clean, err := resolveFsPath(p)
		if err != nil {
			t.Errorf("contract: any host absolute path must be accepted; resolveFsPath(%q) = %v", p, err)
		}
		if clean != p {
			t.Errorf("contract: resolveFsPath must return the cleaned path unchanged for already-clean inputs; got %q want %q", clean, p)
		}
	}
}

func TestFsPathContract_RejectsRelativePath(t *testing.T) {
	t.Parallel()

	cases := []string{
		"foo",
		"./bar",
		"../etc/passwd",
		"",
	}
	for _, p := range cases {
		if _, err := resolveFsPath(p); err == nil {
			t.Errorf("contract: relative or empty path must be rejected; resolveFsPath(%q) returned nil error", p)
		}
	}
}

// 显式钉死“没有 sandbox 根目录”：这里列出多条看起来‘敏感’的绝对路径，
// resolveFsPath 必须全部接受。换言之，本测试若失败，等于上层引入了 agent
// 内的 sandbox 概念——这是契约级变更，需要同时更新此测试与 mcp_handlers.go
// 的注释。
func TestFsPathContract_NoSandboxRoot(t *testing.T) {
	t.Parallel()

	for _, p := range sensitiveAbsolutePaths() {
		if _, err := resolveFsPath(p); err != nil {
			t.Errorf("contract: agent does not sandbox FS paths; resolveFsPath(%q) must not reject the path itself, got %v", p, err)
		}
	}
}
