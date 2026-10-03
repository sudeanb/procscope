//go:build linux && amd64

package ptrace

import (
	"syscall"
	"unsafe"
)

// peekData reads one word of tracee memory via PTRACE_PEEKDATA.
func peekData(pid int, addr uint64, out *uint64) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_PEEKDATA,
		uintptr(pid), uintptr(addr), uintptr(unsafe.Pointer(out)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// getEventMsg fetches PTRACE_GETEVENTMSG (e.g. the new child pid).
func getEventMsg(pid int, out *int) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE, syscall.PTRACE_GETEVENTMSG,
		uintptr(pid), 0, uintptr(unsafe.Pointer(out)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// errnoName renders negative return values the way strace does.
func errnoName(ret int64) string {
	if ret >= 0 {
		return ""
	}
	if n, ok := errnos[-ret]; ok {
		return n
	}
	return "EUNKNOWN"
}

var errnos = map[int64]string{
	1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 6: "ENXIO",
	7: "E2BIG", 8: "ENOEXEC", 9: "EBADF", 10: "ECHILD", 11: "EAGAIN",
	12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 15: "ENOTBLK", 16: "EBUSY",
	17: "EEXIST", 18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR", 21: "EISDIR",
	22: "EINVAL", 23: "ENFILE", 24: "EMFILE", 25: "ENOTTY", 26: "ETXTBSY",
	27: "EFBIG", 28: "ENOSPC", 29: "ESPIPE", 30: "EROFS", 31: "EMLINK",
	32: "EPIPE", 33: "EDOM", 34: "ERANGE", 35: "EDEADLK", 36: "ENAMETOOLONG",
	37: "ENOLCK", 38: "ENOSYS", 39: "ENOTEMPTY", 40: "ELOOP",
}
