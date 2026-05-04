package server

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func TestStream_WriteAndReadAt(t *testing.T) {
	s := newStream()
	s.Write([]byte("hello world"))

	reader := s.Reader(context.Background())
	buf := make([]byte, 11)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 11 {
		t.Errorf("n = %d, want 11", n)
	}
	if string(buf[:n]) != "hello world" {
		t.Errorf("data = %q, want %q", string(buf[:n]), "hello world")
	}
}

func TestStream_ReadAtOffset(t *testing.T) {
	s := newStream()
	s.Write([]byte("hello world"))

	reader := s.Reader(context.Background())
	buf := make([]byte, 5)
	n, err := reader.ReadAt(buf, 6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
	if string(buf[:n]) != "world" {
		t.Errorf("data = %q, want %q", string(buf[:n]), "world")
	}
}

func TestStream_ReadAtBlocksUntilWrite(t *testing.T) {
	s := newStream()
	reader := s.Reader(context.Background())

	var (
		mu      sync.Mutex
		gotData string
		gotN    int
		gotErr  error
		done    = make(chan struct{})
	)

	go func() {
		buf := make([]byte, 5)
		n, err := reader.ReadAt(buf, 0)
		mu.Lock()
		gotData = string(buf[:n])
		gotN = n
		gotErr = err
		mu.Unlock()
		close(done)
	}()

	// Give the goroutine time to block on ReadAt.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("ReadAt returned before data was written")
	default:
	}

	s.Write([]byte("hello"))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadAt did not unblock after Write")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr != nil {
		t.Errorf("unexpected error: %v", gotErr)
	}
	if gotN != 5 || gotData != "hello" {
		t.Errorf("got n=%d data=%q, want n=5 data=%q", gotN, gotData, "hello")
	}
}

func TestStream_ReadAtBlocksUntilClose(t *testing.T) {
	s := newStream()
	reader := s.Reader(context.Background())

	done := make(chan struct{})
	var gotErr error

	go func() {
		buf := make([]byte, 10)
		_, gotErr = reader.ReadAt(buf, 0)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("ReadAt returned before Close")
	default:
	}

	s.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadAt did not unblock after Close")
	}

	if gotErr != io.EOF {
		t.Errorf("err = %v, want io.EOF", gotErr)
	}
}

func TestStream_ReadAtBlocksUntilContextCancel(t *testing.T) {
	s := newStream()
	ctx, cancel := context.WithCancel(context.Background())
	reader := s.Reader(ctx)

	done := make(chan struct{})
	var gotN int
	var gotErr error

	go func() {
		buf := make([]byte, 10)
		gotN, gotErr = reader.ReadAt(buf, 0)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("ReadAt returned before context cancel")
	default:
	}

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ReadAt did not unblock after context cancel")
	}

	if gotN != 0 {
		t.Errorf("n = %d, want 0", gotN)
	}
	if gotErr != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", gotErr)
	}
}

func TestStream_ReadAtReturnsEOFWhenClosed(t *testing.T) {
	s := newStream()
	s.Write([]byte("data"))
	s.Close()

	reader := s.Reader(context.Background())
	buf := make([]byte, 10)
	n, err := reader.ReadAt(buf, 0)
	if err != io.EOF {
		t.Errorf("err = %v, want io.EOF", err)
	}
	if n != 4 || string(buf[:n]) != "data" {
		t.Errorf("got n=%d data=%q, want n=4 data=%q", n, string(buf[:n]), "data")
	}
}

func TestStream_ReadAtPastEndOfClosedStream(t *testing.T) {
	s := newStream()
	s.Write([]byte("data"))
	s.Close()

	reader := s.Reader(context.Background())
	buf := make([]byte, 10)
	n, err := reader.ReadAt(buf, 100)
	if err != io.EOF {
		t.Errorf("err = %v, want io.EOF", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

func TestStream_MultipleWrites(t *testing.T) {
	s := newStream()
	s.Write([]byte("hello "))
	s.Write([]byte("world"))

	reader := s.Reader(context.Background())
	buf := make([]byte, 20)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(buf[:n]) != "hello world" {
		t.Errorf("data = %q, want %q", string(buf[:n]), "hello world")
	}
}

func TestStream_IncrementalRead(t *testing.T) {
	s := newStream()
	reader := s.Reader(context.Background())

	s.Write([]byte("first"))

	buf := make([]byte, 5)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("first read error: %v", err)
	}
	if string(buf[:n]) != "first" {
		t.Errorf("first read = %q, want %q", string(buf[:n]), "first")
	}

	done := make(chan struct{})
	var secondData string

	go func() {
		buf2 := make([]byte, 6)
		n2, _ := reader.ReadAt(buf2, 5)
		secondData = string(buf2[:n2])
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	s.Write([]byte("second"))

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second ReadAt did not unblock")
	}

	if secondData != "second" {
		t.Errorf("second read = %q, want %q", secondData, "second")
	}
}

func TestStream_WriteReturnsCount(t *testing.T) {
	s := newStream()
	n, err := s.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
}

func TestStream_ConcurrentReaders(t *testing.T) {
	s := newStream()
	s.Write([]byte("concurrent"))

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader := s.Reader(context.Background())
			buf := make([]byte, 10)
			n, err := reader.ReadAt(buf, 0)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if string(buf[:n]) != "concurrent" {
				t.Errorf("data = %q, want %q", string(buf[:n]), "concurrent")
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent readers timed out")
	}
}

func TestStream_ReadSmallBuffer(t *testing.T) {
	s := newStream()
	s.Write([]byte("hello world"))

	reader := s.Reader(context.Background())
	buf := make([]byte, 3)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 || string(buf) != "hel" {
		t.Errorf("got n=%d data=%q, want n=3 data=%q", n, string(buf), "hel")
	}
}

func TestStream_ReadSmallBufferAtOffset(t *testing.T) {
	s := newStream()
	s.Write([]byte("hello world"))

	reader := s.Reader(context.Background())
	buf := make([]byte, 3)
	n, err := reader.ReadAt(buf, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 || string(buf) != "llo" {
		t.Errorf("got n=%d data=%q, want n=3 data=%q", n, string(buf), "hel")
	}
}

func TestStream_ReadLargeBuffer(t *testing.T) {
	s := newStream()
	s.Write([]byte("hello world"))

	reader := s.Reader(context.Background())
	buf := make([]byte, 12)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantData := "hello world\x00"
	if n != 11 || string(buf) != wantData {
		t.Errorf("got n=%d data=%q, want n=11 data=%q", n, string(buf), wantData)
	}
}

func TestStream_ReadLargeBufferAtOffset(t *testing.T) {
	s := newStream()
	s.Write([]byte("hello world"))

	reader := s.Reader(context.Background())
	buf := make([]byte, 12)
	n, err := reader.ReadAt(buf, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantData := "llo world\x00\x00\x00"
	if n != 9 || string(buf) != wantData {
		t.Errorf("got n=%d data=%q, want n=9 data=%q", n, string(buf), wantData)
	}
}

func TestStream_ImplementsStreamInterface(t *testing.T) {
	var _ Stream = newStream()
}
