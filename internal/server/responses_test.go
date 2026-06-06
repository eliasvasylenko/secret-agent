package server

import (
	"context"
	"testing"
	"time"
)

func TestReadStreamChunk_pollTimeoutReturnsEmpty(t *testing.T) {
	s := newStream()
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	got, err := readStreamChunk(ctx, s, 0, 64)
	if err != nil {
		t.Fatalf("readStreamChunk: %v", err)
	}
	if got.Complete {
		t.Fatal("expected incomplete response on poll timeout")
	}
	if len(got.Data) != 0 {
		t.Fatalf("data = %q, want empty", got.Data)
	}
}

func TestReadStreamChunk_returnsBufferedDataBeforeTimeout(t *testing.T) {
	s := newStream()
	s.Write([]byte("hi"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, err := readStreamChunk(ctx, s, 0, 64)
	if err != nil {
		t.Fatalf("readStreamChunk: %v", err)
	}
	if got.Complete {
		t.Fatal("stream still open")
	}
	if string(got.Data) != "hi" {
		t.Fatalf("data = %q, want hi", got.Data)
	}
}

func TestReadStreamChunk_eofOnClosedStream(t *testing.T) {
	s := newStream()
	s.Write([]byte("done"))
	s.Close()

	got, err := readStreamChunk(context.Background(), s, 0, 64)
	if err != nil {
		t.Fatalf("readStreamChunk: %v", err)
	}
	if !got.Complete {
		t.Fatal("expected complete on EOF")
	}
	if string(got.Data) != "done" {
		t.Fatalf("data = %q, want done", got.Data)
	}
	got, err = readStreamChunk(context.Background(), s, int64(len("done")), 64)
	if err != nil {
		t.Fatalf("readStreamChunk at EOF: %v", err)
	}
	if !got.Complete || len(got.Data) != 0 {
		t.Fatalf("got = %+v, want empty complete", got)
	}
}
