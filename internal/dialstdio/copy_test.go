package dialstdio

import (
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestCopy_rawCopiesBytes(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	peerCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		peerCh <- c
	}()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- Copy(socket, inR, outW) }()

	peer := <-peerCh
	defer peer.Close()

	if _, err := inW.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ping" {
		t.Fatalf("unix got %q", got)
	}

	if _, err := peer.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(outR, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("stdio got %q", got)
	}

	_ = inW.Close()
	_ = peer.Close()
	_ = outW.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Copy hung")
	}
}

func TestCopy_badSocket(t *testing.T) {
	err := Copy(filepath.Join(t.TempDir(), "missing.sock"), nil, io.Discard)
	if err == nil {
		t.Fatal("want dial error")
	}
}

func TestCopy_stdoutFinishesBeforeStdinEOF(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	inR, inW := io.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- Copy(socket, inR, io.Discard) }()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Copy hung waiting for stdin EOF")
	}
	_ = inW.Close()
}
