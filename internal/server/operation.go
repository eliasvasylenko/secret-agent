package server

import (
	"context"
	"io"
	"sync"
)

type operation struct {
	Stdout    Stream
	Stderr    Stream
	Stdin     Stream
	startedBy string
	done      chan struct{}

	mu       sync.Mutex
	exitCode *int
}

func (op *operation) processExitCode() *int {
	op.mu.Lock()
	defer op.mu.Unlock()
	return op.exitCode
}

type Stream interface {
	io.Closer
	io.Reader
	io.Writer
	AsyncReader(ctx context.Context) io.ReaderAt
	AsyncWriter() io.WriterAt
}
