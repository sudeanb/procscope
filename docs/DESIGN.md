# ProcScope design

## Pipeline

    ptrace tracer (or /proc sampler)  →  event channel  →  filter
        →  sink (rolling window + optional JSONL recording)
        →  WebSocket hub  →  dashboard (feed, heatmap, tree)

## Sources

1. **ptrace** (`internal/ptrace`, linux/amd64): the root command runs
   with `PTRACE_TRACEME`; every tracee (root plus forked/vforked/cloned
   descendants, thanks to `PTRACE_O_TRACE{FORK,VFORK,CLONE,EXEC}`) is
   driven with `PTRACE_SYSCALL`. Enter/exit register pairs become one
   event per syscall: number (name from `internal/syscalls`), six raw
   arguments, return value with an strace-style errno name, duration in
   microseconds, and — for the ~14 path-taking syscalls — the decoded
   path, peeked word-by-word out of tracee memory.
2. **eBPF** (`internal/ebpftrace`, optional): `make bpf` compiles
   `bpf/counter.bpf.c` with clang to `counter.bpf.o`; cilium/ebpf loads
   it and attaches to `raw_tracepoint/sys_enter`. A per-CPU array counts
   syscalls by number. The whole package degrades gracefully — without
   the object, or without privileges, procscope logs and continues in
   ptrace-only mode.
3. **/proc** (`internal/proc`): two-snapshot jiffy deltas for CPU%,
   RSS from stat page counts, parent links for the tree panel.

## Event model

One JSON object per event on the wire (`internal/event`):

    {"kind":"syscall","pid":123,"comm":"cat",
     "syscall":{"nr":257,"name":"openat","args":[...],"ret":3,
                "dur_us":11,"ts":"..."},
     "path":"/etc/hostname"}

`spawn` and `exit` events carry the process tree changes.

## Filter language

`pid=42 comm=curl syscall=open* path=/etc/**` — space-separated
`k=v` terms, AND semantics. `*` never crosses `/` in paths; `**` does;
a pattern without slashes/globs matches the file name only. Parsed once
server-side (`internal/filter`, unit-tested), applied again client-side
for instant re-filtering without a reconnect storm.

## Dashboard

Embed-only static assets (`web/`, `go:embed`), no build step. The page
keeps a rolling 4k-event buffer, renders the newest 250 rows, a
per-second × top-syscall heatmap (last 60s) and the process tree. The
WebSocket re-arms with the current filter; the server replays its
rolling window to every new connection so a fresh tab is never blank.
`procscope replay --file` serves the same dashboard over a recorded
JSONL session — which is also how the GitHub Pages preview works.

## Limits

Single host. Path decoding caps at 128 bytes. Heap churn: one event per
syscall — trace a `make` and the channel pressure is real; the sink
window is capped and slow dashboards drop rather than block the
collector. eBPF attach needs root or CAP_BPF+CAP_PERFMON.
