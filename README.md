# ProcScope — process tracing with a live dashboard

ProcScope watches what a Linux command actually does: it traces the
whole process tree with **ptrace**, decodes every syscall (name, raw
arguments, return value, errno, duration, decoded path arguments), and
streams it into a real-time dashboard — syscall feed, per-second
activity heatmap, process tree, top-syscall table — over WebSocket.

```
procscope serve --filter 'syscall=open* path=/etc/**' -- ./your-server
# open http://localhost:8080
```

```
procscope trace -- /bin/ls          # strace-style JSON lines on stdout
procscope ps                        # live process tree with CPU%
procscope replay --file session.jsonl   # dashboard over a recording
```

## Architecture

```
ptrace tracer (root + descendants)  ─┐
eBPF syscall counter (optional)      ├─→ filter → sink → WebSocket → dashboard
/proc tree sampler (CPU%, RSS)      ─┘
```

- **ptrace** (`internal/ptrace`, linux/amd64): `PTRACE_SYSCALL` on every
  tracee; `PTRACE_O_TRACE{FORK,VFORK,CLONE,EXEC}` so children join the
  session automatically. Enter/exit register pairs are merged into one
  event with duration; `openat`-family paths are peeked out of tracee
  memory.
- **eBPF** (`internal/ebpftrace`, optional): `make bpf` compiles a
  standalone `raw_tracepoint/sys_enter` counter (per-CPU array, no
  kernel headers) with clang; cilium/ebpf loads it at runtime. Missing
  object or missing privileges → clean ptrace-only fallback.
- **filters** (`internal/filter`): `pid=42 comm=curl syscall=open*
  path=/etc/**` — glob semantics documented in `docs/DESIGN.md`,
  unit-tested, applied server-side and re-applied client-side.
- **dashboard** (`web/`, go:embed): no framework, no build step;
  rolling 4k-event window, newest-250 feed, 60s × top-syscall heatmap.

## Repository layout

    cmd/procscope/        CLI: trace | ps | serve | replay
    internal/ptrace/      linux/amd64 tracer (syscall-stop decoding)
    internal/proc/        /proc tree + CPU deltas
    internal/syscalls/    x86-64 syscall name table
    internal/filter/      filter language + tests
    internal/ebpftrace/   optional eBPF counter (cilium/ebpf)
    bpf/                  the eBPF program source (clang -target bpf)
    web/                  embedded dashboard (HTML/JS/CSS)
    testdata/             a recorded session for replay + CI
    playground/           GitHub Pages demo (replay mode)

## Requirements

Linux on x86-64, Go 1.18+. Tracing your own children needs no
privileges. The eBPF counter needs root (or CAP_BPF+CAP_PERFMON) and
clang for `make bpf`; everything works without it.

See `docs/DESIGN.md` for the full design and `docs/` for limits.

MIT licensed. Part of a 100-project systems-programming campaign.
