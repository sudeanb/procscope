// Package ebpftrace attaches an optional eBPF program that counts
// syscalls at the raw sys_enter tracepoint — the low-overhead counter
// behind the dashboard's heatmap. Everything here degrades gracefully:
// without the compiled object or without privileges, procscope simply
// runs in ptrace-only mode.
package ebpftrace

import (
	"bytes"
	"embed"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:embed all:bpf_objects
var objects embed.FS

type Counter struct {
	objs  *ebpf.Collection
	links []link.Link
	mu    sync.Mutex
}

// Start loads bpf_objects/counter.bpf.o and attaches it to
// raw_tracepoint/sys_enter. Call Close when done.
func Start() (*Counter, error) {
	obj, err := objects.ReadFile("bpf_objects/counter.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("counter.bpf.o not compiled (see bpf_objects/README.md): %w", err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(obj))
	if err != nil {
		return nil, fmt.Errorf("parse bpf object: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load bpf program: %w (needs privileges or kernel < 5.x)", err)
	}
	c := &Counter{objs: coll}
	tp, ok := coll.Programs["count_sys_enter"]
	if !ok {
		c.Close()
		return nil, fmt.Errorf("bpf object has no count_sys_enter program")
	}
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:     "sys_enter",
		Program:  tp,
	})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("attach raw tracepoint: %w", err)
	}
	c.links = append(c.links, l)
	return c, nil
}

// Counts returns syscall-number -> occurrences since start.
func (c *Counter) Counts() map[uint32]uint64 {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[uint32]uint64, 512)
	for nr := uint32(0); nr < 512; nr++ {
		var perCPU []uint64
		if err := c.objs.Maps["counts"].Lookup(nr, &perCPU); err != nil {
			continue
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		if sum > 0 {
			out[nr] = sum
		}
	}
	return out
}

func (c *Counter) Close() {
	if c == nil {
		return
	}
	for _, l := range c.links {
		l.Close()
	}
	c.objs.Close()
}
