package client

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

func TestNew_rejectsBadURL(t *testing.T) {
	_, err := New("http://")
	if err == nil {
		t.Fatal("want error for URL with no host")
	}
	_, err = New("ssh://agent.example")
	if err == nil {
		t.Fatal("want error for unsupported scheme")
	}
	_, err = New("unix://localhost/tmp/foo.sock")
	if err == nil {
		t.Fatal("want error for unix URL with host")
	}
}

func TestNew_unixURL(t *testing.T) {
	socket := t.TempDir() + "/agent.sock"
	c, err := New("unix://" + socket)
	if err != nil {
		t.Fatal(err)
	}
	if c.endpoint.address.Scheme != "unix" || c.endpoint.address.Path != socket {
		t.Fatalf("endpoint address = %+v", c.endpoint.address)
	}
	req, err := c.buildRequest(t.Context(), http.MethodGet, "/secrets", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.String(); got != "http://unix/secrets" {
		t.Errorf("request URL = %q, want http://unix/secrets", got)
	}
}

func TestNew_httpsRequestURL(t *testing.T) {
	c, err := New("https://agent.example:8443/v1/")
	if err != nil {
		t.Fatal(err)
	}
	req, err := c.buildRequest(t.Context(), http.MethodGet, "/secrets", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := req.URL.String()
	want := "https://agent.example:8443/v1/secrets"
	if got != want {
		t.Errorf("request URL = %q, want %q", got, want)
	}
}

func TestUpgradeAttach_http(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serveAttachOnce(t, ln, http.StatusSwitchingProtocols)

	c, err := New("http://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.upgrade(t.Context(), "/secrets/sid/attach/stdin")
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer conn.Close()
}

func TestUpgradeAttach_https(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secrets/sid/attach/stdout" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("Upgrade") != server.AttachUpgradeProtocol {
			t.Errorf("upgrade = %s", r.Header.Get("Upgrade"))
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("no hijacker")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
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
		if err := resp.Write(bufrw); err != nil {
			return
		}
		_ = bufrw.Flush()
	}))
	defer srv.Close()

	c := testClient(t, srv.URL, testTLS(srv))
	conn, err := c.upgrade(t.Context(), "/secrets/sid/attach/stdout")
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer conn.Close()
}

func TestClient_httpsCatalog(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/secrets" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(server.ItemsResponse[secrets.Secrets]{
			Items: secrets.Secrets{"s1": {Id: "s1", Version: 1}},
		})
	}))
	defer srv.Close()

	c := testClient(t, srv.URL, testTLS(srv))
	got, err := c.Catalog().Secrets().List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := got["s1"]; !ok {
		t.Fatalf("items = %+v", got)
	}
}

func serveAttachOnce(t *testing.T, ln net.Listener, status int) {
	t.Helper()
	go func() {
		conn, err := ln.Accept()
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
		if !strings.HasPrefix(req.URL.Path, "/secrets/") {
			t.Errorf("path = %s", req.URL.Path)
		}
		resp := &http.Response{
			StatusCode: status,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header:     http.Header{"Content-Length": []string{"0"}},
		}
		if status == http.StatusSwitchingProtocols {
			resp.Header.Set("Connection", "Upgrade")
			resp.Header.Set("Upgrade", server.AttachUpgradeProtocol)
		}
		_ = resp.Write(conn)
	}()
}

func testClient(t *testing.T, address string, tlsConfig *tls.Config) *SecretClient {
	t.Helper()
	ep, err := parseEndpoint(address)
	if err != nil {
		t.Fatal(err)
	}
	ep.tls = tlsConfig
	return &SecretClient{endpoint: ep, client: ep.httpClient()}
}

func testTLS(srv *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: pool}
}
