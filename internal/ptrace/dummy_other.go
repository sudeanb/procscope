//go:build !linux || !amd64

package ptrace

import (
	"fmt"

	"procscope/internal/event"
)

// Tracer is a placeholder for non-Linux builds.
type Tracer struct{}

// Start reports the unsupported platform cleanly.
func Start(argv []string) (*Tracer, error) {
	return nil, fmt.Errorf("procscope ptrace requires linux/amd64")
}

// Events is never callable off Linux.
func (t *Tracer) Events(func(event.Event)) error { return fmt.Errorf("unsupported platform") }
