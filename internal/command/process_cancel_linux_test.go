//go:build linux

package command

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Cancelling kills the script's children, not only the shell.
func TestProcess_cancelKillsTheWholeProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	cmd := New("sleep 60 & echo $! > "+pidFile+"; wait", nil, "")
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devnull.Close() })
	files := Files{Fds: []*os.File{devnull, devnull, devnull}, Tty: NoTty}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Process(ctx, files, Environment{}) }()

	pid := waitForPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Process after cancel = nil, want error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Process did not return after cancel")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("child %d survived cancel", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The script has its own session, so no terminal is its controlling terminal.
func TestProcess_runsInANewSession(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	// Field 6 of /proc/<pid>/stat is the session id.
	cmd := New(`read -r _ _ _ _ _ sid _ < /proc/$$/stat; echo "$sid $$" > `+out, nil, "")
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devnull.Close() })
	files := Files{Fds: []*os.File{devnull, devnull, devnull}, Tty: NoTty}
	if err := cmd.Process(context.Background(), files, Environment{}); err != nil {
		t.Fatalf("Process: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(data))
	if len(fields) != 2 || fields[0] != fields[1] {
		t.Fatalf("session id and pid = %q, want the script to lead its own session", data)
	}
}

func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.HasSuffix(string(data), "\n") {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("script never wrote its child's pid")
	return 0
}

// processGone reports whether the process has exited. A zombie awaiting reaping counts as gone.
func processGone(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	rest := string(data[strings.LastIndexByte(string(data), ')')+1:])
	fields := strings.Fields(rest)
	return len(fields) > 0 && fields[0] == "Z"
}
