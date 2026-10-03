package main

import (
	"encoding/json"
	"time"

	"procscope/internal/event"
	"procscope/internal/filter"
)

func writeTimeout() time.Time { return time.Now().Add(5 * time.Second) }

// bridge pipes tracer events into the sink window and the hub broadcast,
// applying the server-side filter first.
func bridge(h *hub, s *sink, in <-chan event.Event, f filter.Filter) {
	for ev := range in {
		if ev.Kind == event.EventSyscall &&
			!f.MatchSyscall(ev.PID, ev.Comm, ev.Syscall.Name, ev.Path) {
			continue
		}
		s.add(ev)
		if line, err := json.Marshal(ev); err == nil {
			h.broadcast(line)
		}
	}
}
