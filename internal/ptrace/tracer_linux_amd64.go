//go:build linux && amd64

// Package ptrace implements a syscall tracer for a whole process tree:
// fork/exec the root under PTRACE_TRACEME, then PTRACE_SYSCALL every
// tracee and decode register pairs (enter/exit) into events.
package ptrace

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"procscope/internal/event"
	"procscope/internal/syscalls"
)

const (
	sigSysgood = 133 // SIGTRAP | 0x80: syscall stop with PTRACE_O_TRACESYSGOOD
	maxStr     = 128 // longest path decoded from tracee memory
)

// Tracee is one traced process (the root or any forked descendant).
type tracee struct {
	pid     int
	comm    string
	inSys   bool           // alternating enter/exit per syscall stop
	enterTS time.Time
	nr      int
	args    [6]uint64
}

// Tracer owns the process tree and emits events until the root exits.
type Tracer struct {
	root    int
	cmd     *exec.Cmd
	mu      sync.Mutex
	onEvent func(event.Event)
	tracees map[int]*tracee
}

// Start launches argv with PTRACE_TRACEME and returns the tracer.
func Start(argv []string) (*Tracer, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %v: %w", argv, err)
	}
	root := cmd.Process.Pid

	// exec stop: the first SIGTRAP after execve(2)
	if os.Getenv("PROCSCOPE_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[dbg] started pid=%d, waiting for exec stop\n", root)
	}
	ws, err := waitStop(root)
	if os.Getenv("PROCSCOPE_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "[dbg] exec stop: ws=%#x exited=%v stop=%v cause=%v err=%v\n",
			uint32(ws), ws.Exited(), ws.StopSignal(), ws.TrapCause(), err)
	}
	if err != nil {
		return nil, err
	}
	if err := setOptions(root); err != nil {
		return nil, err
	}
	t := &Tracer{root: root, tracees: map[int]*tracee{root: {pid: root, comm: base(argv[0])}}}
	// keep the child handle alive so the kernel does not reparent mid-run
	t.cmd = cmd

	// the tracee is stopped at the exec-stop; Events() waits BEFORE it
	// resumes, so kick the first PTRACE_SYSCALL here or nothing moves.
	if err := syscall.PtraceSyscall(root, 0); err != nil {
		return nil, fmt.Errorf("resume after exec stop: %w", err)
	}
	return t, nil
}

func waitStop(pid int) (syscall.WaitStatus, error) {
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(pid, &ws, 0, nil)
	return ws, err
}

func setOptions(pid int) error {
	return syscall.PtraceSetOptions(pid,
		syscall.PTRACE_O_TRACESYSGOOD|
			syscall.PTRACE_O_TRACEFORK|
			syscall.PTRACE_O_TRACEVFORK|
			syscall.PTRACE_O_TRACECLONE|
			syscall.PTRACE_O_TRACEEXEC)
}

// Events runs the tracer loop until the root process exits, invoking on
// every decoded syscall event. Callbacks must not block.
func (t *Tracer) Events(onEvent func(event.Event)) error {
	t.onEvent = onEvent
	debug := os.Getenv("PROCSCOPE_DEBUG") != ""
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if debug {
			fmt.Fprintf(os.Stderr, "[dbg] wait4 pid=%d ws=%#x exited=%v signaled=%v stop=%v cause=%v err=%v\n",
				pid, uint32(ws), ws.Exited(), ws.Signaled(), ws.StopSignal(), ws.TrapCause(), err)
		}
		if err != nil {
			if err == syscall.ECHILD {
				return nil // nothing left to wait on
			}
			return err
		}

		switch {
		case ws.Exited():
			t.mu.Lock()
			comm := ""
			if tr := t.tracees[pid]; tr != nil {
				comm = tr.comm
			}
			delete(t.tracees, pid)
			t.mu.Unlock()
			if onEvent != nil {
				onEvent(event.Event{Kind: event.EventExit, PID: pid, Comm: comm})
			}
			if pid == t.root {
				return nil
			}
			continue

		case ws.Signaled():
			t.mu.Lock()
			_, ok := t.tracees[pid]
			delete(t.tracees, pid)
			t.mu.Unlock()
			if pid == t.root || !ok {
				return nil
			}
			continue
		}

		st := ws.StopSignal()

		// NOTE: Go's StopSignal() returns the stop signal UNMASKED:
		// a syscall stop with PTRACE_O_TRACESYSGOOD reads as 133
		// (SIGTRAP|0x80), and TrapCause() is only meaningful for a
		// plain SIGTRAP. Branch on 133 FIRST or the syscall stop is
		// mistaken for signal delivery and the tracee never resumes.
		if st == sigSysgood {
			t.decodeSyscallStop(pid, &ws)
			continue
		}
		if st != syscall.SIGTRAP {
			// signal-delivery or group stop: pass it through and resume
			syscall.PtraceSyscall(pid, int(st))
			continue
		}
		if ws.TrapCause() == (syscall.PTRACE_EVENT_FORK<<8 | int(syscall.SIGTRAP)) ||
			ws.TrapCause() == (syscall.PTRACE_EVENT_VFORK<<8 | int(syscall.SIGTRAP)) ||
			ws.TrapCause() == (syscall.PTRACE_EVENT_CLONE<<8 | int(syscall.SIGTRAP)) {
			// a new tracee was born: learn its pid, set its options
			var child int
			if err := getEventMsg(pid, &child); err == nil && child > 0 {
				if err := setOptions(child); err == nil {
					t.mu.Lock()
					parent := t.tracees[pid]
					comm := ""
					if parent != nil {
						comm = parent.comm
					}
					t.tracees[child] = &tracee{pid: child, comm: comm}
					t.mu.Unlock()
					if onEvent != nil {
						onEvent(event.Event{Kind: event.EventSpawn, PID: child, PPID: pid, Comm: comm})
					}
				}
			}
			syscall.PtraceSyscall(pid, 0)
			continue
		}
		if ws.TrapCause() == (syscall.PTRACE_EVENT_EXEC<<8 | int(syscall.SIGTRAP)) {
			t.mu.Lock()
			if tr := t.tracees[pid]; tr != nil {
				tr.comm = readComm(pid, tr.comm)
			}
			t.mu.Unlock()
			syscall.PtraceSyscall(pid, 0)
			continue
		}
		// plain breakpoint or other SIGTRAP: resume without decoding
		syscall.PtraceSyscall(pid, 0)
	}
}

// decodeSyscallStop handles one sysgood stop: alternating enter/exit
// register snapshots merged into a single event per syscall.
func (t *Tracer) decodeSyscallStop(pid int, ws *syscall.WaitStatus) {
	dbg := os.Getenv("PROCSCOPE_DEBUG") != ""
	var regs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
		if dbg {
			fmt.Fprintf(os.Stderr, "[dbg] getregs err: %v\n", err)
		}
		syscall.PtraceSyscall(pid, 0)
		return
	}
	if dbg {
		fmt.Fprintf(os.Stderr, "[dbg] decode pid=%d nr=%d rax=%#x\n", pid, regs.Orig_rax, regs.Rax)
	}

	t.mu.Lock()
	tr := t.tracees[pid]
	if tr == nil {
		tr = &tracee{pid: pid}
		t.tracees[pid] = tr
	}
	tr.inSys = !tr.inSys
	if tr.inSys { // syscall ENTER
		tr.enterTS = time.Now()
		tr.nr = int(regs.Orig_rax)
		tr.args = [6]uint64{regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9}
		t.mu.Unlock()
		if dbg {
			fmt.Fprintf(os.Stderr, "[dbg] enter resume\n")
		}
		syscall.PtraceSyscall(pid, 0)
		return
	}
	// syscall EXIT
	sc := &event.Syscall{
		NR:    tr.nr,
		Name:  syscalls.Name(tr.nr),
		Args:  tr.args,
		Ret:   int64(regs.Rax),
		Err:   errnoName(int64(regs.Rax)),
		DurUs: time.Since(tr.enterTS).Microseconds(),
		TS:    tr.enterTS,
	}
	ev := event.Event{Kind: event.EventSyscall, PID: pid, Comm: tr.comm, Syscall: sc}
	t.mu.Unlock()
	if dbg {
		fmt.Fprintf(os.Stderr, "[dbg] exit decode, peeking path\n")
	}
	ev.Path = decodePath(pid, sc.NR, sc.Args)
	if dbg {
		fmt.Fprintf(os.Stderr, "[dbg] emit event\n")
	}
	if t.onEvent != nil {
		t.onEvent(ev)
	}
	syscall.PtraceSyscall(pid, 0)
}

// readString peeks a NUL-terminated C string out of tracee memory.
func readString(pid int, addr uint64) string {
	if addr == 0 {
		return ""
	}
	var b strings.Builder
	for off := 0; off < maxStr; off += 8 {
		var word uint64
		if err := peekData(pid, addr+uint64(off), &word); err != nil {
			break
		}
		for i := 0; i < 8; i++ {
			c := byte(word >> (8 * i))
			if c == 0 {
				return b.String()
			}
			b.WriteByte(c)
		}
	}
	return b.String()
}

// pathArg maps the few syscalls whose string argument the arena decodes
// to their argument slot; everything else yields "".
var pathArg = map[int]int{
	2: 0,   // open
	59: 0,  // execve
	80: 0,  // chdir
	85: 0,  // creat
	87: 0,  // unlink
	89: 0,  // readlink
	21: 0,  // access
	4: 0,   // stat
	257: 1, // openat
	262: 1, // unlinkat
	263: 1, // renameat (first path only)
	268: 1, // faccessat
	437: 1, // openat2
}

func decodePath(pid, nr int, args [6]uint64) string {
	slot, ok := pathArg[nr]
	if !ok {
		return ""
	}
	return readString(pid, args[slot])
}

func readComm(pid int, fallback string) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(data))
}

func base(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

