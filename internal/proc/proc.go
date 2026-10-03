// Package proc turns /proc into a live process tree with CPU deltas.
package proc

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Proc is one process snapshot row.
type Proc struct {
	PID    int     `json:"pid"`
	PPID   int     `json:"ppid"`
	Comm   string  `json:"comm"`
	State  string  `json:"state"`
	CPUPct float64 `json:"cpu_pct"`
	RSSKB  uint64  `json:"rss_kb"`

	cpuTicks uint64 // internal: raw jiffies for the next delta
}

type snap struct {
	cpuTicks uint64
	at       time.Time
}

var prev = map[int]snap{}

// Tree returns all processes with parent links and CPU% measured
// against the previous call (user+system jiffies delta over wall time).
func Tree() []Proc {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []Proc
	cur := map[int]snap{}
	clk := clockTicks()
	now := time.Now()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a numeric proc dir
		}
		p, ok := readStat(pid)
		if !ok {
			continue
		}
		ticks := p.cpuTicks
		if s, ok := prev[pid]; ok && now.After(s.at) {
			dt := now.Sub(s.at).Seconds()
			if dt > 0 {
				p.CPUPct = 100 * float64(ticks-s.cpuTicks) / clk / dt
			}
		}
		cur[pid] = snap{cpuTicks: ticks, at: now}
		out = append(out, p)
	}
	prevUnlockedReplace(cur)
	return out
}

// prev is guarded by Tree's single-caller usage in this binary; tests
// call Tree sequentially too.
func prevUnlockedReplace(cur map[int]snap) { prev = cur }

func readStat(pid int) (Proc, bool) {
	var p Proc
	p.PID = pid
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return p, false
	}
	s := string(data)
	// comm is in parentheses and may contain spaces: split on the LAST ')'
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 > len(s) {
		return p, false
	}
	p.Comm = strings.Trim(s[1:i], "()")
	rest := strings.Fields(s[i+2:])
	if len(rest) < 20 {
		return p, false
	}
	p.State = rest[0]
	p.PPID, _ = strconv.Atoi(rest[1])
	utime, _ := strconv.ParseUint(rest[11], 10, 64)
	stime, _ := strconv.ParseUint(rest[12], 10, 64)
	rssPages, _ := strconv.ParseUint(rest[21], 10, 64)
	p.cpuTicks = utime + stime
	p.RSSKB = rssPages * uint64(pageSize()) / 1024
	return p, true
}

func clockTicks() float64  { return 100 } // _SC_CLK_TCK is 100 on every Linux userspace
func pageSize() int        { return os.Getpagesize() }
