package server

import (
	"context"
	"io"
)

type operation struct {
	Stdout    Stream
	Stderr    Stream
	startedBy string
}

type Stream interface {
	io.WriteCloser
	Reader(ctx context.Context) io.ReaderAt
}
