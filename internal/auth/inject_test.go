package auth

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/dialstdio"
)

func TestInjectForwardedUser(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		header string
		err    error
	}
	gotCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			gotCh <- result{err: err}
			return
		}
		defer c.Close()
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			gotCh <- result{err: err}
			return
		}
		_, _ = io.ReadAll(req.Body)
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		gotCh <- result{header: req.Header.Get(DefaultForwardAuthHeader)}
	}()

	req := "GET /secrets HTTP/1.1\r\nHost: unix\r\n\r\n"
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := InjectForwardedUser(conn, bytes.NewReader([]byte(req)), "john", "")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := dialstdio.Proxy(conn, rest, &out); err != nil {
		t.Fatal(err)
	}

	got := <-gotCh
	if got.err != nil {
		t.Fatal(got.err)
	}
	if got.header != "john" {
		t.Fatalf("header = %q", got.header)
	}
	if !bytes.Contains(out.Bytes(), []byte("ok")) {
		t.Fatalf("response %q", out.Bytes())
	}
}

func TestInjectForwardedUser_replacesExisting(t *testing.T) {
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
		gotCh <- req.Header.Get(DefaultForwardAuthHeader)
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	req := "GET /secrets HTTP/1.1\r\nHost: unix\r\nX-Secret-Agent-User: mallory\r\n\r\n"
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := InjectForwardedUser(conn, bytes.NewReader([]byte(req)), "john", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = dialstdio.Proxy(conn, rest, io.Discard)

	if got := <-gotCh; got != "john" {
		t.Fatalf("header = %q, want john", got)
	}
}

func TestInjectForwardedUser_customHeader(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotCh := make(chan http.Header, 1)
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
		gotCh <- req.Header.Clone()
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()

	req := "GET /secrets HTTP/1.1\r\nHost: unix\r\n\r\n"
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := InjectForwardedUser(conn, bytes.NewReader([]byte(req)), "john", "X-Remote-User")
	if err != nil {
		t.Fatal(err)
	}
	_ = dialstdio.Proxy(conn, rest, io.Discard)

	got := <-gotCh
	if got.Get("X-Remote-User") != "john" {
		t.Fatalf("X-Remote-User = %q", got.Get("X-Remote-User"))
	}
	if got.Get(DefaultForwardAuthHeader) != "" {
		t.Fatalf("default header = %q", got.Get(DefaultForwardAuthHeader))
	}
}

func TestInjectForwardedUser_forwardsUnreadBytes(t *testing.T) {
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
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			gotCh <- "read request: " + err.Error()
			return
		}
		if req.Header.Get(DefaultForwardAuthHeader) != "john" {
			gotCh <- "header = " + req.Header.Get(DefaultForwardAuthHeader)
			return
		}
		extra := make([]byte, 4)
		if _, err := io.ReadFull(br, extra); err != nil {
			gotCh <- "read extra: " + err.Error()
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		gotCh <- string(extra)
	}()

	req := "POST /secrets/s/attach/stdin HTTP/1.1\r\nHost: unix\r\nContent-Length: 0\r\n\r\nraw!"
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	rest, err := InjectForwardedUser(conn, bytes.NewReader([]byte(req)), "john", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = dialstdio.Proxy(conn, rest, io.Discard)

	select {
	case got := <-gotCh:
		if got != "raw!" {
			t.Fatalf("extra = %q, want raw!", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server hung")
	}
}
