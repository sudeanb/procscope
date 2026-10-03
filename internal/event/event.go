// Package event defines the telemetry flowing from collector to dashboard.
package event

import "time"

// Kind discriminates event types on the stream.
type Kind string

const (
	EventSyscall Kind = "syscall"
	EventSpawn   Kind = "spawn"
	EventExit    Kind = "exit"
)

// Syscall is one traced system call: enter, optional exit, or both merged.
type Syscall struct {
	NR     int    `json:"nr"`
	Name   string `json:"name"`
	Args   [6]uint64 `json:"args"`
	Ret    int64  `json:"ret"`
	Err    string `json:"err,omitempty"`
	DurUs  int64  `json:"dur_us"`
	TS     time.Time `json:"ts"`
}

// Event is what the collector emits and the dashboard renders.
type Event struct {
	Kind    Kind    `json:"kind"`
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid,omitempty"`
	Comm    string  `json:"comm"`
	Syscall *Syscall `json:"syscall,omitempty"`
	Path    string  `json:"path,omitempty"` // decoded for path-taking syscalls
}
