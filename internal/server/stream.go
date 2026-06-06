package server

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type stream struct {
	mu   sync.Mutex
	cond *sync.Cond
	buf  bytes.Buffer
	base int64
	done chan struct{}
}

type streamAsyncReader struct {
	stream *stream
	ctx    context.Context
}

type streamAsyncWriter struct {
	stream *stream
}

func newStream() *stream {
	s := &stream{}
	s.done = make(chan struct{})
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	default:
		close(s.done)
		s.cond.Broadcast()
		return nil
	}
}

func (s *stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.readAt(context.Background(), p, s.base)
	if n > 0 {
		_ = s.trim(s.base + int64(n))
	}
	return n, err
}

func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeAt(p, s.base+int64(s.buf.Len()))
}

func (s *stream) readAt(ctx context.Context, p []byte, off int64) (int, error) {
	readDone := make(chan struct{})
	defer close(readDone)
	go func() {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.cond.Broadcast()
			s.mu.Unlock()
		case <-readDone:
		}
	}()

	if err := s.trim(off); err != nil {
		return 0, err
	}

	for s.buf.Len() == 0 {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-s.done:
			if s.buf.Len() == 0 {
				return 0, io.EOF
			}
		default:
		}
		s.cond.Wait()
	}

	data := s.buf.Bytes()
	endExclusive := int64(len(data)) + s.base

	rel := int(off - s.base)
	n := copy(p, data[rel:])

	select {
	case <-s.done:
		if int64(n)+off >= endExclusive {
			return n, io.EOF
		}
	default:
	}
	return n, nil
}

func (s *stream) writeAt(p []byte, off int64) (int, error) {
	select {
	case <-s.done:
		return 0, io.ErrClosedPipe
	default:
	}

	if len(p) == 0 {
		return 0, nil
	}

	// Entire write falls below the consumed/read frontier.
	if off+int64(len(p)) <= s.base {
		return len(p), nil
	}

	// Drop the portion already consumed below base.
	if off < s.base {
		skip := int(s.base - off)
		if skip >= len(p) {
			return len(p), nil
		}
		p = p[skip:]
		off = s.base
	}

	// Pad the buffer up to the write index
	rel := int(off - s.base)
	gap := rel - s.buf.Len()
	if gap > 0 {
		padding := make([]byte, gap)
		s.buf.Write(padding)
	}

	// Overlap with existing buffered data: copy in place, append only the tail.
	if gap < 0 {
		n := copy(s.buf.Bytes()[rel:], p)
		p = p[n:]
	}

	s.buf.Write(p)
	s.cond.Broadcast()
	return len(p), nil
}

func (s *stream) trim(off int64) error {
	delta := off - s.base
	if delta < 0 {
		return NewErrorResponse(http.StatusConflict,
			fmt.Errorf("stream index %d is before current base %d", off, s.base))
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

func (s *stream) AsyncReader(ctx context.Context) io.ReaderAt {
	return &streamAsyncReader{stream: s, ctx: ctx}
}

func (r *streamAsyncReader) ReadAt(p []byte, off int64) (int, error) {
	r.stream.mu.Lock()
	defer r.stream.mu.Unlock()
	return r.stream.readAt(r.ctx, p, off)
}

func (s *stream) AsyncWriter() io.WriterAt {
	return &streamAsyncWriter{stream: s}
}

func (w *streamAsyncWriter) WriteAt(p []byte, off int64) (int, error) {
	w.stream.mu.Lock()
	defer w.stream.mu.Unlock()
	return w.stream.writeAt(p, off)
}
