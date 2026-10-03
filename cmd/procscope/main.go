// Command procscope traces a command's syscalls live (ptrace, with an
// optional eBPF assist), snapshots the process tree and serves a real-time
// web dashboard over WebSocket.
//
//	procscope trace [--filter EXPR] -- ./cmd args...
//	procscope ps
//	procscope serve [--addr :8080] [--filter EXPR] [--record FILE] -- ./cmd
//	procscope replay --file FILE [--addr :8080]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"procscope/internal/ebpftrace"
	"procscope/internal/event"
	"procscope/internal/filter"
	"procscope/internal/proc"
	"procscope/internal/ptrace"
)

func usage() { fmt.Fprintln(os.Stderr, strings.TrimSpace(documentation)) ; os.Exit(2) }

const documentation = `
usage:
  procscope trace [--filter EXPR] -- CMD [ARGS...]
  procscope ps
  procscope serve [--addr :8080] [--filter EXPR] [--record FILE] -- CMD [ARGS...]
  procscope replay --file FILE [--addr :8080]
`

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "trace":
		cmdTrace(os.Args[2:])
	case "ps":
		cmdPS()
	case "serve":
		cmdServe(os.Args[2:])
	case "replay":
		cmdReplay(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
	}
}

// splitDoubleDash: everything after -- belongs to the traced command.
func splitDoubleDash(args []string) (flags []string, cmd []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func cmdTrace(argv []string) {
	flags, cmd := splitDoubleDash(argv)
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	expr := fs.String("filter", "", `e.g. 'syscall=open* path=/etc/**'`)
	fs.Parse(flags)
	if len(cmd) == 0 {
		usage()
	}
	f := mustFilter(*expr)

	tr, events, done := runTracer(cmd)
	for ev := range events {
		if ev.Kind == event.EventSyscall && !f.MatchSyscall(ev.PID, ev.Comm, ev.Syscall.Name, ev.Path) {
			continue
		}
		line, _ := json.Marshal(ev)
		fmt.Println(string(line))
	}
	<-done
	_ = tr
}

func cmdPS() {
	for _, p := range proc.Tree() {
		fmt.Printf("%7d %7d %-4s %-18s %5.1f%% %8dKB\n",
			p.PID, p.PPID, p.State, p.Comm, p.CPUPct, p.RSSKB)
	}
}

func cmdServe(argv []string) {
	flags, cmd := splitDoubleDash(argv)
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	expr := fs.String("filter", "", "server-side event filter")
	record := fs.String("record", "", "write all events to this JSON-lines file")
	ebpfFlag := fs.Bool("ebpf", false, "also attach the eBPF syscall counter (needs privileges)")
	fs.Parse(flags)

	f := mustFilter(*expr)

	if len(cmd) == 0 && *record == "" {
		// no child: dashboard over the whole system's process tree only
		log.Println("no child command: serving process-tree dashboard only")
	}
	sink := newSink(*record)

	var counter *ebpftrace.Counter
	if *ebpfFlag {
		if c, err := ebpftrace.Start(); err != nil {
			log.Printf("eBPF counter disabled: %v", err)
		} else {
			counter = c
			log.Printf("eBPF syscall counter attached")
		}
	}
	_ = counter // exposed on /summary below

	hub := newHub()
	if len(cmd) > 0 {
		tr, events, done := runTracer(cmd)
		_ = tr
		go func() {
			bridge(hub, sink, events, f)
			<-done
		}()
	}

	go http.ListenAndServe(*addr, routes(hub, sink))
	log.Printf("dashboard on http://localhost%s", *addr)
	select {}
}

func cmdReplay(argv []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	file := fs.String("file", "", "JSON-lines event file")
	fs.Parse(argv)
	if *file == "" {
		usage()
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	var evs []event.Event
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev event.Event
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Kind != "" {
			evs = append(evs, ev)
		}
	}
	log.Printf("replaying %d events", len(evs))
	hub := newHub()
	sink := newSink("")
	for _, ev := range evs {
		sink.add(ev)
	}
	go http.ListenAndServe(*addr, routes(hub, sink))
	log.Printf("dashboard on http://localhost%s", *addr)
	select {}
}

func mustFilter(expr string) filter.Filter {
	f, err := filter.Parse(expr)
	if err != nil {
		log.Fatalf("bad filter: %v", err)
	}
	return f
}

// runTracer starts the child and pumps events into a channel.
func runTracer(cmd []string) (*ptrace.Tracer, <-chan event.Event, <-chan struct{}) {
	tr, err := ptrace.Start(cmd)
	if err != nil {
		log.Fatalf("ptrace: %v", err)
	}
	events := make(chan event.Event, 1024)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(events)
		if err := tr.Events(func(ev event.Event) {
			events <- ev
		}); err != nil {
			log.Printf("tracer ended: %v", err)
		}
	}()
	return tr, events, done
}

// sink keeps the recent event window for new dashboard clients.
type sink struct {
	mu     sync.Mutex
	events []event.Event
	path   string
}

func newSink(path string) *sink { return &sink{path: path} }

const windowMax = 5000

func (s *sink) add(ev event.Event) {
	s.mu.Lock()
	s.events = append(s.events, ev)
	if len(s.events) > windowMax {
		s.events = s.events[len(s.events)-windowMax:]
	}
	s.mu.Unlock()
	if s.path != "" {
		if line, err := json.Marshal(ev); err == nil {
			f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			if err == nil {
				f.WriteString(string(line) + "\n")
				f.Close()
			}
		}
	}
}

func (s *sink) window() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]event.Event, len(s.events))
	copy(out, s.events)
	return out
}

var _ = time.Now
