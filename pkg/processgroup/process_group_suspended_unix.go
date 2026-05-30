//go:build !windows

package processgroup

import "os/exec"

// NewSuspendedExecCommand is a portability shim. On POSIX the suspended
// flow is unnecessary: the unix process group is set via setpgid before
// the kernel returns from execve, so the pgid kill path in
// process_group.go reaps every descendant that stays in the leader's
// group. Descendants that call setsid()/setpgid() escape that group and
// are NOT covered (see killProcessGroupHard). Returning a plain exec.Cmd
// keeps callers portable.
func NewSuspendedExecCommand(name string, args ...string) *exec.Cmd {
	return NewExecCommand(name, args...)
}

// ResumeMainThread is a no-op on POSIX. Windows uses it to release the
// main thread after binding the process to its JobObject; on Linux/macOS
// the binding already happened pre-exec.
func ResumeMainThread(cmd *exec.Cmd) error {
	return nil
}
