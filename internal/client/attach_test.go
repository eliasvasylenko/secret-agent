package client

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

func TestUpgradeAttach_ok(t *testing.T) {
	ctx := context.Background()
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		if req.Method != http.MethodPost {
			t.Errorf("method = %s", req.Method)
		}
		if req.URL.Path != "/operations/op1/attach" {
			t.Errorf("path = %s", req.URL.Path)
		}
		if req.Header.Get("Upgrade") != server.AttachUpgradeProtocol {
			t.Errorf("upgrade = %s", req.Header.Get("Upgrade"))
		}
		if req.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %s", req.Header.Get("Content-Type"))
		}
		var body server.AttachRequest
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Errorf("decode attach body: %v", err)
		}
		if len(body.Fds) != 1 || body.Fds[0] != 0 || body.Mode != command.Read {
			t.Errorf("attach body = %+v", body)
		}

		resp := &http.Response{
			StatusCode: http.StatusSwitchingProtocols,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Connection": []string{"Upgrade"},
				"Upgrade":    []string{server.AttachUpgradeProtocol},
			},
		}
		if err := resp.Write(conn); err != nil {
			t.Errorf("write 101: %v", err)
		}
	}()

	conn, err := openAttach(mustUnixClient(t, socket), ctx, "op1", command.FileGroup{Fds: []int{0}, Mode: command.Read})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer conn.Close()
}

func TestUpgradeAttach_rejectsNon101(t *testing.T) {
	ctx := context.Background()
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = http.ReadRequest(bufio.NewReader(conn))
		_, _ = conn.Write([]byte("HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n"))
	}()

	_, err = mustUnixClient(t, socket).upgrade(ctx, "/operations/op1/attach", nil)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "426") {
		t.Fatalf("err = %v", err)
	}
}

func TestAttachAll_closesPriorOnFailure(t *testing.T) {
	priorClient, priorServer := net.Pipe()
	t.Cleanup(func() { _ = priorServer.Close() })

	calls := 0
	stubAttach(t, func(_ context.Context, _ string, _ command.FileGroup) (io.ReadWriteCloser, error) {
		calls++
		if calls == 1 {
			return priorClient, nil
		}
		return nil, io.ErrUnexpectedEOF
	})
	c := &SecretClient{}

	first, firstW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = first.Close()
		_ = firstW.Close()
	})
	secondR, second, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = secondR.Close()
		_ = second.Close()
	})
	_, err = (&httpRunner{client: c}).attachAll(context.Background(), "op1", command.FileGroups{
		{Fds: []int{0}, Mode: command.Read, File: first},
		{Fds: []int{1}, Mode: command.Write, File: second},
	})
	if err == nil {
		t.Fatal("want error")
	}
	if calls != 2 {
		t.Fatalf("dials = %d, want the first to succeed and the second to fail", calls)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := priorServer.Read(buf)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err != io.EOF {
			t.Fatalf("prior conn read = %v, want EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("prior conn was not closed")
	}
}

func mustUnixClient(t *testing.T, socket string) *SecretClient {
	t.Helper()
	c, err := New(socket)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
