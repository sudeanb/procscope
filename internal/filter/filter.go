// Package filter parses procscope's filter language:
//
//	pid=42 comm=curl syscall=open* path=/etc/**
//
// Space-separated k=v terms, AND semantics. `pid` is exact, `comm`
// matches the process name, `syscall` and `path` accept * (any run of
// characters, not crossing a `/` for path) and ** (anything) globs.
package filter

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

type Filter struct {
	PID     int
	hasPID  bool
	Comm    string
	Syscall string
	Path    string
}

// Parse compiles a filter expression. Empty input matches everything.
func Parse(expr string) (Filter, error) {
	f := Filter{PID: -1}
	for _, term := range strings.Fields(expr) {
		k, v, ok := strings.Cut(term, "=")
		if !ok {
			return f, fmt.Errorf("term %q is not k=v", term)
		}
		switch k {
		case "pid":
			n, err := strconv.Atoi(v)
			if err != nil {
				return f, fmt.Errorf("pid=%q is not a number", v)
			}
			f.PID, f.hasPID = n, true
		case "comm":
			f.Comm = v
		case "syscall":
			f.Syscall = v
		case "path":
			f.Path = v
		default:
			return f, fmt.Errorf("unknown key %q (want pid|comm|syscall|path)", k)
		}
	}
	return f, nil
}

// MatchSyscall reports whether a traced syscall event passes.
func (f Filter) MatchSyscall(pid int, comm, syscall string, path string) bool {
	if f.hasPID && pid != f.PID {
		return false
	}
	if f.Comm != "" && !glob(f.Comm, comm) {
		return false
	}
	if f.Syscall != "" && !glob(f.Syscall, syscall) {
		return false
	}
	if f.Path != "" && !matchPath(f.Path, path) {
		return false
	}
	return true
}

// matchPath: * stays within one path segment, ** crosses them. A filter
// without any slash matches on the file NAME at the end of the path.
func matchPath(pattern, path string) bool {
	if path == "" {
		return false
	}
	if !strings.ContainsAny(pattern, "*/") {
		return pattern == filepath.Base(path)
	}
	if strings.Contains(pattern, "**") {
		return globAll(pattern, path)
	}
	ok, err := filepath.Match(pattern, path)
	if err != nil {
		return false
	}
	if ok {
		return true
	}
	// also allow matching a suffix like /etc/* against /etc/hosts/fstab? no:
	// fall back to base match for patterns like *.conf
	ok, err = filepath.Match(pattern, filepath.Base(path))
	return err == nil && ok
}

// glob is filepath.Match restricted to strings without path semantics.
func glob(pattern, s string) bool {
	ok, err := filepath.Match(pattern, s)
	return err == nil && ok
}

// globAll converts ** to a permissive single-* match over the whole path.
func globAll(pattern, path string) bool {
	flat := strings.ReplaceAll(pattern, "**", "\x00")
	flat = strings.ReplaceAll(flat, "*", "\x01")
	re := regexpQuote(flat)
	return re(path)
}

// regexpQuote builds a tiny matcher for the flattened pattern without
// pulling in the regexp package's per-call compilation cost in the hot
// path; filters are compiled once by the caller so this is fine.
func regexpQuote(p string) func(string) bool {
	var lit []rune
	var parts []string
	for _, r := range p {
		switch r {
		case '\x00':
			if len(lit) > 0 {
				parts = append(parts, quote(string(lit)))
				lit = nil
			}
			parts = append(parts, ".*")
		case '\x01':
			if len(lit) > 0 {
				parts = append(parts, quote(string(lit)))
				lit = nil
			}
			parts = append(parts, "[^/]*")
		default:
			lit = append(lit, r)
		}
	}
	if len(lit) > 0 {
		parts = append(parts, quote(string(lit)))
	}
	full := "^" + strings.Join(parts, "") + "$"
	return func(s string) bool {
		return matchHere(full, s)
	}
}
