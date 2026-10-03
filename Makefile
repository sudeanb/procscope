# ProcScope build. Requires Go 1.18+; the eBPF object additionally
# needs clang with the BPF target.

GO      ?= go
CLANG   ?= clang

all: procscope

procscope:
	$(GO) build -o procscope ./cmd/procscope

test:
	$(GO) vet ./...
	$(GO) test ./...

# Optional: compile the eBPF syscall counter (needs clang -target bpf).
bpf: bpf/counter.bpf.c
	$(CLANG) -O2 -g -Wall -target bpf -c bpf/counter.bpf.c -o internal/ebpftrace/bpf_objects/counter.bpf.o

trace-demo: procscope
	./procscope trace --filter 'syscall=open*' -- /bin/cat /etc/hostname

clean:
	rm -f procscope internal/ebpftrace/bpf_objects/counter.bpf.o

.PHONY: all test bpf trace-demo clean
