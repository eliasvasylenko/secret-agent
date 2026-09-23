package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/dialstdio"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

func TestMain(m *testing.M) {
	if socket := os.Getenv("SECRET_AGENT_TEST_DIAL_STDIO"); socket != "" {
		in := io.Reader(os.Stdin)
		if user := os.Getenv("SECRET_AGENT_TEST_DIAL_STDIO_USER"); user != "" {
			conn, err := net.Dial("unix", socket)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			in, err = auth.InjectForwardedUser(conn, os.Stdin, user, "")
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := dialstdio.Proxy(conn, in, os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		} else if err := dialstdio.Copy(socket, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestClient_sshCatalog(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/secrets" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(server.ItemsResponse[secrets.Secrets]{
			Items: secrets.Secrets{"s1": {Id: "s1", Version: 1}},
		})
	}))

	mockDialStdio(t, socket, "")

	c, err := New("ssh://eli@testhost")
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Catalog().Secrets().List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if _, ok := got["s1"]; !ok {
		t.Fatalf("items = %+v", got)
	}
}

func TestClient_sshCatalog_sharedAccountHeader(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(auth.DefaultForwardAuthHeader) != "john" {
			t.Errorf("header = %q", r.Header.Get(auth.DefaultForwardAuthHeader))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(server.ItemsResponse[secrets.Secrets]{
			Items: secrets.Secrets{"s1": {Id: "s1", Version: 1}},
		})
	}))

	mockDialStdio(t, socket, "john")

	c, err := New("ssh://eli@testhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Catalog().Secrets().List(t.Context()); err != nil {
		t.Fatalf("List: %v", err)
	}
}

func TestClient_sshAttach(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serveAttachOnce(t, ln, http.StatusSwitchingProtocols)
	mockDialStdio(t, socket, "")

	c, err := New("ssh://eli@testhost")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := c.upgrade(t.Context(), "/secrets/sid/attach/stdin")
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	defer conn.Close()
}

func TestNew_sshURL(t *testing.T) {
	c, err := New("ssh://eli@agent.example:2222")
	if err != nil {
		t.Fatal(err)
	}
	if c.endpoint.address.Scheme != "ssh" || c.endpoint.address.Host != "agent.example:2222" {
		t.Fatalf("endpoint = %+v", c.endpoint.address)
	}
	req, err := c.buildRequest(t.Context(), http.MethodGet, "/secrets", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.String(); got != "http://unix/secrets" {
		t.Errorf("request URL = %q, want http://unix/secrets", got)
	}
}

func TestDialSSH_startFails(t *testing.T) {
	old := sshExec
	t.Cleanup(func() { sshExec = old })
	sshExec = func(ctx context.Context, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/nonexistent/secret-agent-ssh-test")
	}
	u, err := url.Parse("ssh://eli@testhost")
	if err != nil {
		t.Fatal(err)
	}
	_, err = dialSSH(t.Context(), u)
	if err == nil {
		t.Fatal("want error when ssh command fails to start")
	}
}

func TestCmdConn_deadlines(t *testing.T) {
	conn := &cmdConn{}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

func TestCmdConn_closeKillsHungProcess(t *testing.T) {
	old := sshWaitAfterClose
	t.Cleanup(func() { sshWaitAfterClose = old })
	sshWaitAfterClose = 50 * time.Millisecond

	cmd := exec.Command("sleep", "30")
	conn, err := startCmdConn(cmd)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_ = conn.Close()
	if time.Since(start) > 2*time.Second {
		t.Fatal("Close hung")
	}
}

func TestSSHArgs(t *testing.T) {
	u, err := url.Parse("ssh://eli@agent.example:2222")
	if err != nil {
		t.Fatal(err)
	}
	got := sshArgs(u)
	if slices.Contains(got, "-p") {
		t.Fatalf("unexpected -p in %v", got)
	}
	if !slices.Contains(got, "ssh://eli@agent.example:2222") {
		t.Fatalf("missing host in %v", got)
	}
	if !slices.Contains(got, "secret-agent dial-stdio") {
		t.Fatalf("missing remote command in %v", got)
	}
	if slices.Contains(got, "-s") {
		t.Fatalf("unexpected -s in %v", got)
	}
}

func TestSSHDestination_ipv6(t *testing.T) {
	u, err := url.Parse("ssh://eli@[::1]:2222")
	if err != nil {
		t.Fatal(err)
	}
	if got := sshDestination(u); got != "ssh://eli@[::1]:2222" {
		t.Fatalf("sshDestination = %q", got)
	}
}

func TestSSHArgs_socketPath(t *testing.T) {
	u, err := url.Parse("ssh://eli@agent.example/run/secret-agent/other.sock")
	if err != nil {
		t.Fatal(err)
	}
	got := sshArgs(u)
	want := "secret-agent dial-stdio -s " + shellQuote("/run/secret-agent/other.sock")
	if !slices.Contains(got, want) {
		t.Fatalf("remote command = %v, want element %q", got, want)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != "'a'\"'\"'b'" {
		t.Fatalf("shellQuote = %q", got)
	}
}

func mockDialStdio(t *testing.T, socket, user string) {
	t.Helper()
	old := sshExec
	t.Cleanup(func() { sshExec = old })
	sshExec = func(ctx context.Context, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
		env := append(os.Environ(), "SECRET_AGENT_TEST_DIAL_STDIO="+socket)
		if user != "" {
			env = append(env, "SECRET_AGENT_TEST_DIAL_STDIO_USER="+user)
		}
		cmd.Env = env
		return cmd
	}
}
