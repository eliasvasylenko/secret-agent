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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/server"
	"golang.org/x/sys/unix"
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

	conn, err := openAttach(mustUnixClient(t, socket), ctx, "op1", fileGroup{fds: []int{0}, mode: command.Read})
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
	stubAttach(t, func(_ context.Context, _ string, _ fileGroup) (io.ReadWriteCloser, error) {
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
	_, err = (&httpRunner{client: c}).attachAll(context.Background(), "op1", command.Files{Fds: []*os.File{first, second}, Tty: command.NoTty})
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

func TestFileGroups_sameFileSharesAttach(t *testing.T) {
	read, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close() })
	dupfd, err := syscall.Dup(int(out.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	same := os.NewFile(uintptr(dupfd), out.Name())
	t.Cleanup(func() { _ = same.Close() })

	groups, err := fileGroups(command.Files{Fds: []*os.File{nil, out, same}, Tty: command.NoTty})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want one shared output and no invented stdin", len(groups))
	}
	shared := groups[0]
	if !hasFds(shared.fds, 1, 2) {
		t.Fatalf("shared fds = %v", shared.fds)
	}
	if shared.mode != command.Write {
		t.Fatalf("shared mode = %s, want w", shared.mode)
	}
	if shared.file != out && shared.file != same {
		t.Fatal("shared output is not written once")
	}
}

func TestFileGroups_dupSeparatedByAnotherFile(t *testing.T) {
	read, out, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = read.Close() })
	dupfd, err := syscall.Dup(int(out.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	same := os.NewFile(uintptr(dupfd), out.Name())
	t.Cleanup(func() { _ = same.Close() })

	path := filepath.Join(t.TempDir(), "other")
	created, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })

	groups, err := fileGroups(command.Files{Fds: []*os.File{out, other, same}, Tty: command.NoTty})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want the dup together and the other file alone", len(groups))
	}
	var dup, alone *fileGroup
	for i := range groups {
		switch len(groups[i].fds) {
		case 2:
			dup = &groups[i]
		case 1:
			alone = &groups[i]
		}
	}
	if dup == nil || alone == nil {
		t.Fatalf("groups = %+v", groups)
	}
	if dup.mode != command.Write || !hasFds(dup.fds, 0, 2) {
		t.Fatalf("dup group = %+v, want write fds 0 and 2", dup)
	}
	if alone.mode != command.Read || alone.fds[0] != 1 {
		t.Fatalf("other group = %+v, want read fd 1", alone)
	}
}

func TestFileGroups_twoOpensAreSeparate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	created, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	groups, err := fileGroups(command.Files{Fds: []*os.File{first, second}, Tty: command.NoTty})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want two opens", len(groups))
	}
}

func TestFileGroups_readWriteFileIsNotAStream(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	_, err = fileGroups(command.Files{Fds: []*os.File{f}, Tty: command.NoTty})
	if err == nil {
		t.Fatal("expected error for O_RDWR file")
	}
}

func TestFileGroups_ttyIndexOnFirstDescriptor(t *testing.T) {
	term := testTerminal(t)
	groups, err := fileGroups(command.Files{Fds: []*os.File{term}, Tty: 0})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want one", len(groups))
	}
	if groups[0].mode != command.Ctty || len(groups[0].fds) != 1 || groups[0].fds[0] != 0 {
		t.Fatalf("group = %+v, want ctty fd 0", groups[0])
	}
}

func TestFileGroups_ttyIndexPromotesGroup(t *testing.T) {
	term := testTerminal(t)
	dupfd, err := syscall.Dup(int(term.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	same := os.NewFile(uintptr(dupfd), term.Name())
	t.Cleanup(func() { _ = same.Close() })

	groups, err := fileGroups(command.Files{Fds: []*os.File{term, same}, Tty: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want one", len(groups))
	}
	group := groups[0]
	if !hasFds(group.fds, 0, 1) {
		t.Fatalf("fds = %v, want 0 and 1", group.fds)
	}
	if group.mode != command.Ctty {
		t.Fatalf("mode = %s, want ctty", group.mode)
	}
}

func hasFds(fds []int, want ...int) bool {
	if len(fds) != len(want) {
		return false
	}
	seen := map[int]bool{}
	for _, fd := range fds {
		seen[fd] = true
	}
	for _, fd := range want {
		if !seen[fd] {
			return false
		}
	}
	return true
}

func testTerminal(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = slave.Close() })
	return slave
}

func mustUnixClient(t *testing.T, socket string) *SecretClient {
	t.Helper()
	c, err := New(socket)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
