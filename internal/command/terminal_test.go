package command

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

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

	slave, master, err := OpenPty()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	// The descriptors are terminals. Process does not Setctty when Tty is
	// NoTty. After Setsid, a session leader with a tty on stdin may still
	// acquire that tty as ctty (bash does); /dev/tty failing is covered by
	// tests that do not pass a terminal on stdio.
	cmd := New("test -t 0 && test -t 1 && test -t 2", nil, "")
	if err := cmd.Process(context.Background(), Files{Fds: []*os.File{slave, slave, slave}, Tty: NoTty}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestProcess_terminalDescriptorsAsCtty(t *testing.T) {
	slave, master, err := OpenPty()
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
	slave, master, err := OpenPty()
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
