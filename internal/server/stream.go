package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
)

var ErrSeekBeforeCurrent = errors.New("read at offset before current stream base")
var ErrSeekAfterEnd = errors.New("read at offset after end of stream")

type stream struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  bytes.Buffer
	base int64
	done chan struct{}
}

type streamReader struct {
	stream *stream
	ctx    context.Context
}

func newStream() *stream {
	s := &stream{}
	s.done = make(chan struct{})
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *stream) trim(off int64) error {
	delta := off - s.base
	if delta < 0 {
		return ErrSeekBeforeCurrent
	} else if delta > int64(s.buf.Len()) {
		s.buf.Reset()
	} else {
		tail := s.buf.Bytes()[delta:]
		s.buf.Reset()
		s.buf.Write(tail)
	}
	s.base = off
	return nil
}

func (s *stream) Reader(ctx context.Context) io.ReaderAt {
	return &streamReader{stream: s, ctx: ctx}
}

func (r *streamReader) ReadAt(p []byte, off int64) (int, error) {
	readDone := make(chan struct{})
	defer close(readDone)
	go func() {
		select {
		case <-r.ctx.Done():
			r.stream.mu.Lock()
			r.stream.cond.Broadcast()
			r.stream.mu.Unlock()
		case <-readDone:
		}
	}()

	r.stream.mu.Lock()
	defer r.stream.mu.Unlock()

	if err := r.stream.trim(off); err != nil {
		return 0, err
	}

	for r.stream.buf.Len() == 0 {
		select {
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		case <-r.stream.done:
			if r.stream.buf.Len() == 0 {
				return 0, io.EOF
			}
		default:
		}
		r.stream.cond.Wait()
	}

	bytes := r.stream.buf.Bytes()
	endExclusive := int64(len(bytes)) + r.stream.base

	if off > endExclusive {
		return 0, ErrSeekAfterEnd
	}

	n := copy(p, bytes)

	select {
	case <-r.stream.done:
		if int64(n)+off >= endExclusive {
			return n, io.EOF
		}
	default:
	}
	return n, nil
}

func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.done)
	s.cond.Broadcast()
	return nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return 0, io.ErrClosedPipe
	default:
	}
	n, err := s.buf.Write(p)
	s.cond.Broadcast()
	return n, err
}
