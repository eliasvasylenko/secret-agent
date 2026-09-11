package client

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

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
		if req.URL.Path != "/secrets/sid/attach/stdin" {
			t.Errorf("path = %s", req.URL.Path)
		}
		if req.Header.Get("Upgrade") != server.AttachUpgradeProtocol {
			t.Errorf("upgrade = %s", req.Header.Get("Upgrade"))
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

	conn, err := upgradeAttach(ctx, socket, "/secrets/sid/attach/stdin")
	if err != nil {
		t.Fatalf("upgradeAttach: %v", err)
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
		_, _ = conn.Write([]byte("HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n"))
	}()

	_, err = upgradeAttach(ctx, socket, "/secrets/sid/attach/stdin")
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "426") {
		t.Fatalf("err = %v", err)
	}
}

func TestAttachAll_closesPriorOnFailure(t *testing.T) {
	stdinClient, stdinServer := net.Pipe()
	t.Cleanup(func() { _ = stdinServer.Close() })

	c := &SecretClient{attach: func(_ context.Context, path string) (*attachConn, error) {
		if strings.HasSuffix(path, "/stdin") {
			return &attachConn{Conn: stdinClient, reader: bufio.NewReader(stdinClient)}, nil
		}
		return nil, io.ErrUnexpectedEOF
	}}

	_, err := c.attachAll(context.Background(), "sid")
	if err == nil {
		t.Fatal("want error")
	}

	buf := make([]byte, 1)
	_, readErr := stdinServer.Read(buf)
	if readErr != io.EOF {
		t.Fatalf("stdin server read = %v, want EOF after cleanup", readErr)
	}
}
