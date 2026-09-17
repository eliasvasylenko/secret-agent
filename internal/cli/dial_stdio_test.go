package cli

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
)

func TestRunDialStdio_injectsUserHeader(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		gotCh <- req.Header.Get(auth.DefaultForwardAuthHeader)
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	req := "GET /secrets HTTP/1.1\r\nHost: unix\r\n\r\n"
	if err := runDialStdio(socket, "john", "", bytes.NewReader([]byte(req)), io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := <-gotCh; got != "john" {
		t.Fatalf("header = %q", got)
	}
}

func TestRunDialStdio_customHeader(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotCh := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return
		}
		gotCh <- req.Header.Get("X-Remote-User")
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	req := "GET /secrets HTTP/1.1\r\nHost: unix\r\n\r\n"
	if err := runDialStdio(socket, "john", "X-Remote-User", bytes.NewReader([]byte(req)), io.Discard); err != nil {
		t.Fatal(err)
	}
	if got := <-gotCh; got != "john" {
		t.Fatalf("header = %q", got)
	}
}
