//go:build windows

package processgroup

import (
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NewSuspendedExecCommand returns a CREATE_SUSPENDED command so the agent
// exec path can attach the JobObject BEFORE any user code in the child
// runs. Without suspended creation, fast-spawning grandchildren can race
// AssignProcessToJobObject and escape the Job — defeating
// TerminateJobObject on timeout. Call ResumeMainThread after AddProcess.
func NewSuspendedExecCommand(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_SUSPENDED,
	}
	return cmd
}

// ResumeMainThread releases the primary thread of a CREATE_SUSPENDED
// process. Callers MUST invoke this after AssignProcessToJobObject,
// otherwise the child stays frozen forever.
func ResumeMainThread(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	tid, err := primaryThreadID(uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, tid)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(thread)
	if _, err := windows.ResumeThread(thread); err != nil {
		return err
	}
	return nil
}

func primaryThreadID(pid uint32) (uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snap)
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	if err := windows.Thread32First(snap, &te); err != nil {
		return 0, err
	}
	for {
		if te.OwnerProcessID == pid {
			return te.ThreadID, nil
		}
		if err := windows.Thread32Next(snap, &te); err != nil {
			return 0, err
		}
	}
}
