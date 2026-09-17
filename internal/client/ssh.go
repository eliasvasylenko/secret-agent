package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
)

func dialSSH(ctx context.Context, u *url.URL) (net.Conn, error) {
	cmd := sshExec(ctx, sshArgs(u)...)
	return startCmdConn(cmd)
}

var sshExec = func(ctx context.Context, args ...string) *exec.Cmd {
	return exec.CommandContext(ctx, "ssh", args...)
}

func sshArgs(u *url.URL) []string {
	args := []string{
		"-T", "-e", "none",
		"-o", "BatchMode=yes",
		"-o", "ClearAllForwardings=yes",
	}
	args = append(args, "--", sshDestination(u), sshRemoteCommand(u))
	return args
}

// sshDestination is an ssh:// URI OpenSSH accepts as DESTINATION (user, host,
// port, IPv6 brackets). Path is the agent socket, not part of the hop.
func sshDestination(u *url.URL) string {
	d := url.URL{Scheme: u.Scheme, Host: u.Host}
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			d.User = url.User(name)
		}
	}
	return d.String()
}

func sshRemoteCommand(u *url.URL) string {
	cmd := "secret-agent dial-stdio"
	if path := u.Path; path != "" && path != "/" {
		cmd += " -s " + shellQuote(path)
	}
	return cmd
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func startCmdConn(cmd *exec.Cmd) (net.Conn, error) {
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, fmt.Errorf("ssh: %w", err)
	}
	return &cmdConn{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

var sshWaitAfterClose = 5 * time.Second

type cmdConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	closed atomic.Bool
}

func (c *cmdConn) Read(p []byte) (int, error)  { return c.stdout.Read(p) }
func (c *cmdConn) Write(p []byte) (int, error) { return c.stdin.Write(p) }

func (c *cmdConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = c.stdin.Close()
	_ = c.stdout.Close()
	done := make(chan error, 1)
	go func() { done <- c.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(sshWaitAfterClose):
		if c.cmd.Process != nil {
			_ = c.cmd.Process.Kill()
		}
		return <-done
	}
}

func (c *cmdConn) LocalAddr() net.Addr  { return cmdAddr("local") }
func (c *cmdConn) RemoteAddr() net.Addr { return cmdAddr("remote") }

func (c *cmdConn) SetDeadline(time.Time) error      { return nil }
func (c *cmdConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cmdConn) SetWriteDeadline(time.Time) error { return nil }

type cmdAddr string

func (a cmdAddr) Network() string { return "ssh" }
func (a cmdAddr) String() string  { return string(a) }
