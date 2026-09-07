package server

import (
	"sync"
)

type operation struct {
	pipes    *operationPipes
	startedBy string
	done     chan struct{}

	attachMu        sync.Mutex
	stdinAttached   bool
	stdoutAttached  bool
	stderrAttached  bool
}
