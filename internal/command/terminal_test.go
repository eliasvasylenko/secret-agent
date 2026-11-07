package command

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLocalMode_readWriteRegularFileIsRefused(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "rw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	_, err = LocalMode(f)
	if err == nil || err.Error() != "read-write file cannot be attached" {
		t.Fatalf("LocalMode error = %v", err)
	}
}

func TestLocalMode_readWriteFifoIsRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	mode, err := LocalMode(f)
	if err != nil {
		t.Fatal(err)
	}
	if mode != Read {
		t.Fatalf("LocalMode = %q, want read", mode)
	}
}

func TestProcess_terminalDescriptorsWithoutCtty(t *testing.T) {
	// A child inherits this process's controlling terminal. Start a new
	// session so /dev/tty stays closed unless Process installs one.
	if os.Getenv("SA_TEST_NO_CTTY") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestProcess_terminalDescriptorsWithoutCtty$")
		cmd.Env = append(os.Environ(), "SA_TEST_NO_CTTY=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		return
	}

	slave, master, err := openTestTerminal()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	// The descriptors are terminals, but none of them is the controlling
	// terminal: /dev/tty must not open.
	cmd := New("test -t 0 && test -t 1 && test -t 2 && ! (exec 3<>/dev/tty)", nil, "")
	if err := cmd.Process(context.Background(), Files{Fds: []*os.File{slave, slave, slave}, Tty: NoTty}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProcess_terminalDescriptorsAsCtty(t *testing.T) {
	slave, master, err := openTestTerminal()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	cmd := New("test -t 0 && test -t 1 && test -t 2 && (exec 3<>/dev/tty)", nil, "")
	if err := cmd.Process(context.Background(), Files{Fds: []*os.File{slave, slave, slave}, Tty: 0}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProcess_distinctCtty(t *testing.T) {
	slave, master, err := openTestTerminal()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	// No stdio descriptor is a terminal, but the process still has a
	// controlling one.
	cmd := New("! test -t 0 && ! test -t 1 && ! test -t 2 && (exec 3<>/dev/tty)", nil, "")
	files := Files{Fds: []*os.File{devNull(t), devNull(t), devNull(t), slave}, Tty: 3}
	if err := cmd.Process(context.Background(), files, nil); err != nil {
		t.Fatal(err)
	}
}

func openTestTerminal() (slave, master *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	if err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return slave, master, nil
}
