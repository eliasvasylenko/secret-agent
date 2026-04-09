package server

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"
)

type stream struct {
	mu          sync.Mutex
	cond        *sync.Cond
	buf         bytes.Buffer
	done        bool
	completedAt time.Time
}

type streamReader struct {
	stream *stream
	ctx    context.Context
}

func newStream() *stream {
	s := &stream{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *stream) Reader(ctx context.Context) io.ReaderAt {
	return &streamReader{stream: s, ctx: ctx}
}

func (r *streamReader) ReadAt(p []byte, off int64) (int, error) {
	r.stream.mu.Lock()
	defer r.stream.mu.Unlock()

	endOff := len(r.stream.buf.Bytes())
	if !r.stream.done && off >= int64(endOff) {
		go func() {
			<-r.ctx.Done()
			r.stream.cond.Broadcast()
		}()

		if !r.stream.done && off >= int64(endOff) {
			r.stream.cond.Wait()
			endOff = len(r.stream.buf.Bytes())
		}
	}

	if off >= int64(endOff) {
		if r.stream.done {
			return 0, io.EOF
		}
		return 0, nil
	}

	n := copy(p, r.stream.buf.Bytes()[off:])
	if r.stream.done && int(off)+n >= endOff {
		return n, io.EOF
	}
	return n, nil
}

func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	s.completedAt = time.Now()
	s.cond.Broadcast()
	return nil
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.buf.Write(p)
	s.cond.Broadcast()
	return n, err
}
