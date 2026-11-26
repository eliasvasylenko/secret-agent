//go:build linux

package command

import (
	"bytes"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenBroker_forwardsOutput(t *testing.T) {
	srcSlave, srcMaster, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer srcMaster.Close()
	defer srcSlave.Close()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()

	broker, err := OpenBroker([]*os.File{inR, srcSlave, srcSlave})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	if broker.Files().Tty != NoTty {
		t.Fatalf("Tty = %d, want none when the terminal is not controlling", broker.Files().Tty)
	}
	if Terminal(broker.Files().Fds[1]) {
		t.Fatal("stdout is still a terminal")
	}

	if _, err := broker.Files().Fds[1].Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	_ = srcMaster.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 5)
	n, err := srcMaster.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("read %q, want hello", buf[:n])
	}
}

func TestOpenBroker_closeKeepsPendingOutput(t *testing.T) {
	srcSlave, srcMaster, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer srcMaster.Close()
	defer srcSlave.Close()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()

	broker, err := OpenBroker([]*os.File{inR, srcSlave, srcSlave})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()

	const size = 32 << 10
	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 8192)
		total := 0
		for total < size {
			n, err := srcMaster.Read(buf)
			total += n
			if err != nil {
				break
			}
		}
		got <- total
	}()

	if _, err := broker.Files().Fds[1].Write(bytes.Repeat([]byte("x"), size)); err != nil {
		t.Fatal(err)
	}
	broker.Close()
	select {
	case n := <-got:
		if n != size {
			t.Fatalf("terminal got %d bytes, want %d", n, size)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("output written before Close did not arrive")
	}
}

func TestOpenBroker_outputOnlyLeavesSettings(t *testing.T) {
	srcSlave, srcMaster, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer srcMaster.Close()
	defer srcSlave.Close()

	before, err := unix.IoctlGetTermios(int(srcSlave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()

	out, errOut := writeOnlyTty(t, srcSlave)
	broker, err := OpenBroker([]*os.File{inR, out, errOut})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()

	after, err := unix.IoctlGetTermios(int(srcSlave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag != after.Lflag {
		t.Fatalf("output terminal Lflag changed: before=%v after=%v", before.Lflag, after.Lflag)
	}
}

func TestOpenBroker_hangsUpLeftover(t *testing.T) {
	srcSlave, srcMaster, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer srcMaster.Close()
	defer srcSlave.Close()

	broker, err := OpenBroker([]*os.File{srcSlave, srcSlave, srcSlave})
	if err != nil {
		t.Fatal(err)
	}
	held, err := unix.Dup(int(broker.Files().Fds[1].Fd()))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(held)

	broker.Close()
	_, err = unix.Write(held, []byte("x"))
	if err != unix.EPIPE {
		t.Fatalf("write after close = %v, want EPIPE", err)
	}
}

func TestOpenBroker_wrapsOnlyTerminals(t *testing.T) {
	srcSlave, srcMaster, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer srcMaster.Close()
	defer srcSlave.Close()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()

	broker, err := OpenBroker([]*os.File{inR, srcSlave, srcSlave})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()

	if len(broker.Groups) != 2 {
		t.Fatalf("Groups = %d, want stdin and a piped terminal", len(broker.Groups))
	}
	var in, out *FileGroup
	for i := range broker.Groups {
		g := &broker.Groups[i]
		if hasFds(g.Fds, 0) {
			in = g
		}
		if hasFds(g.Fds, 1, 2) {
			out = g
		}
	}
	if in == nil || in.File != inR || in.Mode != Read {
		t.Fatalf("stdin group = %+v", in)
	}
	if out == nil || out.File == srcSlave || Terminal(out.File) || out.Mode != Write {
		t.Fatalf("stdout group = %+v", out)
	}
	if broker.Files().Fds[0] != inR {
		t.Fatal("stdin was rewritten")
	}
	if broker.Files().Fds[1] != out.File || broker.Files().Fds[2] != out.File {
		t.Fatal("stdout and stderr do not share the pipe")
	}
}

func TestOpenBroker_readWritePassesThrough(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	broker, err := OpenBroker([]*os.File{f, f, f})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	if len(broker.Groups) != 1 {
		t.Fatalf("Groups = %d, want one open", len(broker.Groups))
	}
	group := broker.Groups[0]
	if group.Mode.Valid() {
		t.Fatalf("mode = %s, want unattachable", group.Mode)
	}
	if group.File != f {
		t.Fatal("read-write file was rewritten")
	}
}

func TestOpenBroker_readsTtyOnOtherFd(t *testing.T) {
	srcSlave, srcMaster, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer srcMaster.Close()
	defer srcSlave.Close()

	before, err := unix.IoctlGetTermios(int(srcSlave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()
	defer outW.Close()
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer errR.Close()
	defer errW.Close()

	broker, err := OpenBroker([]*os.File{inR, outW, errW, srcSlave})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()

	after, err := unix.IoctlGetTermios(int(srcSlave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag != after.Lflag {
		t.Fatalf("non-controlling terminal Lflag changed: before=%v after=%v", before.Lflag, after.Lflag)
	}
	script := broker.Files().Fds[3]
	var extra *FileGroup
	for i := range broker.Groups {
		if hasFds(broker.Groups[i].Fds, 3) {
			extra = &broker.Groups[i]
		}
	}
	if extra == nil || extra.Mode != Write || Terminal(script) {
		t.Fatalf("fd 3 group = %+v", extra)
	}
	if _, err := script.Write([]byte("xy")); err != nil {
		t.Fatal(err)
	}
	_ = srcMaster.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2)
	n, err := srcMaster.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "xy" {
		t.Fatalf("read %q, want xy", buf[:n])
	}
}

func TestOpenBroker_writeOnlyOnStdinLeavesSettings(t *testing.T) {
	srcSlave, srcMaster, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer srcMaster.Close()
	defer srcSlave.Close()

	before, err := unix.IoctlGetTermios(int(srcSlave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := writeOnlyTty(t, srcSlave)
	broker, err := OpenBroker([]*os.File{in})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()

	after, err := unix.IoctlGetTermios(int(srcSlave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag != after.Lflag {
		t.Fatalf("write-only stdin Lflag changed: before=%v after=%v", before.Lflag, after.Lflag)
	}
}

func writeOnlyTty(t *testing.T, slave *os.File) (out, errOut *os.File) {
	t.Helper()
	out, err := os.OpenFile(slave.Name(), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	fd, err := unix.Dup(int(out.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	errOut = os.NewFile(uintptr(fd), slave.Name())
	t.Cleanup(func() { errOut.Close() })
	return out, errOut
}

func TestOwnTerminals_chownsToCredential(t *testing.T) {
	slave, master, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	ownTerminals(CommandOptions{Credential: &syscall.Credential{Uid: uid, Gid: gid}}, Files{Fds: []*os.File{slave}})

	var stat unix.Stat_t
	if err := unix.Fstat(int(slave.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Uid != uid || stat.Gid != gid {
		t.Fatalf("slave owner = %d:%d, want %d:%d", stat.Uid, stat.Gid, uid, gid)
	}
}
