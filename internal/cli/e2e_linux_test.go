//go:build linux

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"golang.org/x/sys/unix"
)

// These tests run the real CLI (this test binary, re-executed by TestMain) with a pseudo
// terminal as its controlling terminal, the way an operator runs it.

// Ctrl-C reaches the CLI only: scripts have their own session. The CLI must cancel, and
// cancelling must take the script's children with it.
func TestCLI_ctrlCStopsTheScriptAndItsChildren(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{
		"s1": "sleep 300 & echo $! > " + pidFile + "; wait",
	})
	run := startOnPTY(t, "-S", secretsFile, "-D", dbFile, "create", "s1")

	pid := waitForPIDFile(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if processGone(pid) {
		t.Fatalf("script's child exited by itself\n%s", run.out)
	}

	if _, err := run.master.Write([]byte{0x03}); err != nil { // ^C
		t.Fatal(err)
	}
	status := run.wait(t, 10*time.Second)

	if status.Signaled() {
		t.Fatalf("CLI was killed by %v instead of cancelling\n%s", status.Signal(), run.out)
	}
	if status.ExitStatus() == 0 {
		t.Fatalf("cancelled create exited 0\n%s", run.out)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("script's child %d survived Ctrl-C\n%s", pid, run.out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The broker gives the script a PTY whose slave is Files.Tty, for both
// local sqlite and HTTP (the address is unused; grouping happens first).
func TestCLI_files_marksOperatorPty(t *testing.T) {
	for _, addr := range []string{"", "unix://x"} {
		run := startOnPTYEnv(t, []string{"SECRET_AGENT_TEST_FILES=" + addr})
		status := run.wait(t, 5*time.Second)
		if status.ExitStatus() != 0 || status.Signaled() {
			t.Fatalf("addr %q: child failed: %v\n%s", addr, status, run.out)
		}
		if got := strings.TrimSpace(run.out.String()); got != "tty=0" {
			t.Fatalf("addr %q: Files.Tty = %q, want tty=0", addr, got)
		}
	}
}

// The script has /dev/tty on its own PTY, not the operator's terminal.
func TestCLI_scriptHasControllingTerminal(t *testing.T) {
	dir := t.TempDir()
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{
		"s1": `if (exec 3</dev/tty) 2>/dev/null; then s=opened; else s=denied; fi; echo "tty-$s"`,
	})
	run := startOnPTY(t, "-S", secretsFile, "-D", dbFile, "create", "s1")

	status := run.wait(t, 10*time.Second)

	if status.ExitStatus() != 0 || status.Signaled() {
		t.Fatalf("create failed: %v\n%s", status, run.out)
	}
	if !strings.Contains(run.out.String(), "tty-opened") {
		t.Fatalf("script could not open /dev/tty\n%s", run.out)
	}
}

func TestCLI_hiddenPassphrase(t *testing.T) {
	dir := t.TempDir()
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{
		"s1": `stty -echo </dev/tty; echo READY >/dev/tty; read -r p </dev/tty; printf 'got:%s\n' "$p"`,
	})
	run := startOnPTY(t, "-S", secretsFile, "-D", dbFile, "create", "s1")
	waitOutput(t, run.out, "READY", 5*time.Second)
	if _, err := run.master.Write([]byte("secret\n")); err != nil {
		t.Fatal(err)
	}
	status := run.wait(t, 10*time.Second)
	if status.ExitStatus() != 0 || status.Signaled() {
		t.Fatalf("create failed: %v\n%s", status, run.out)
	}
	out := run.out.String()
	if !strings.Contains(out, "got:secret") {
		t.Fatalf("passphrase not received:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(strings.TrimSuffix(line, "\r")) == "secret" {
			t.Fatalf("passphrase echoed:\n%s", out)
		}
	}
}

func TestCLI_promptOnDevTTYStdoutRedirected(t *testing.T) {
	dir := t.TempDir()
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{
		"s1": `echo prompt-on-tty >/dev/tty`,
	})
	master, slave := openPTY(t)
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdoutR.Close() })

	cmd := exec.Command(os.Args[0], "-S", secretsFile, "-D", dbFile, "create", "s1")
	cmd.Env = append(os.Environ(), "SECRET_AGENT_TEST_CLI=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, stdoutW, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = slave.Close()
	_ = stdoutW.Close()

	var termOut, jsonOut lockedBuffer
	copied := make(chan struct{})
	jsonDone := make(chan struct{})
	go func() { _, _ = io.Copy(&termOut, master); close(copied) }()
	go func() { _, _ = io.Copy(&jsonOut, stdoutR); close(jsonDone) }()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); <-copied; <-jsonDone; close(done) }()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("CLI still running\nterm:%s\njson:%s", &termOut, &jsonOut)
	}
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if status.ExitStatus() != 0 || status.Signaled() {
		t.Fatalf("create failed: %v\nterm:%s\njson:%s", status, &termOut, &jsonOut)
	}
	if !strings.Contains(termOut.String(), "prompt-on-tty") {
		t.Fatalf("prompt missing from terminal\n%s", &termOut)
	}
	jsonBytes := jsonOut.String()
	brace := strings.Index(jsonBytes, "{")
	if brace < 0 || strings.Contains(jsonBytes[:brace], "prompt-on-tty") {
		t.Fatalf("prompt leaked onto stdout\n%s", jsonBytes)
	}
}

func TestCLI_leftoverWriterHungUp(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{
		"s1": `(while true; do echo leftover >/dev/tty || exit; sleep 0.1; done) & echo $! > ` + pidFile,
	})
	run := startOnPTY(t, "-S", secretsFile, "-D", dbFile, "create", "s1")
	pid := waitForPIDFile(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	status := run.wait(t, 10*time.Second)
	if status.ExitStatus() != 0 || status.Signaled() {
		t.Fatalf("create failed: %v\n%s", status, run.out)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !processGone(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("leftover %d still running after hangup\n%s", pid, run.out)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCLI_otherTtySettingsUnchanged(t *testing.T) {
	dir := t.TempDir()
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{
		"s1": `if test -t 1; then echo stdout-tty >/dev/tty; else echo stdout-pipe >/dev/tty; fi`,
	})
	opMaster, opSlave := openPTY(t)
	otherMaster, otherSlave := openPTY(t)
	before, err := unix.IoctlGetTermios(int(otherSlave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-S", secretsFile, "-D", dbFile, "create", "s1")
	cmd.Env = append(os.Environ(), "SECRET_AGENT_TEST_CLI=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = opSlave, otherSlave, opSlave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = opSlave.Close()
	_ = otherSlave.Close()

	var termOut lockedBuffer
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&termOut, opMaster); close(copied) }()
	go func() { _, _ = io.Copy(io.Discard, otherMaster) }()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); <-copied; close(done) }()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("CLI still running\n%s", &termOut)
	}
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if status.ExitStatus() != 0 || status.Signaled() {
		t.Fatalf("create failed: %v\n%s", status, &termOut)
	}
	if !strings.Contains(termOut.String(), "stdout-pipe") {
		t.Fatalf("script stdout was a terminal\n%s", &termOut)
	}
	after, err := unix.IoctlGetTermios(int(otherMaster.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag&unix.ECHO != after.Lflag&unix.ECHO {
		t.Fatalf("output terminal ECHO changed: before=%v after=%v", before.Lflag&unix.ECHO != 0, after.Lflag&unix.ECHO != 0)
	}
}

func TestCLI_httpScriptHasControllingTerminal(t *testing.T) {
	dir := t.TempDir()
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{
		"s1": `if (exec 3</dev/tty) 2>/dev/null; then s=opened; else s=denied; fi; echo "tty-$s"`,
	})
	socket := startServe(t, secretsFile, dbFile)
	run := startOnPTY(t, "-a", "unix://"+socket, "create", "s1")
	status := run.wait(t, 15*time.Second)
	if status.ExitStatus() != 0 || status.Signaled() {
		t.Fatalf("http create failed: %v\n%s", status, run.out)
	}
	if !strings.Contains(run.out.String(), "tty-opened") {
		t.Fatalf("http script could not open /dev/tty\n%s", run.out)
	}
}

// serve does not observe the context, so it must keep the default signal handling or
// `systemctl stop` would hang.
func TestCLI_serveStopsOnSIGTERM(t *testing.T) {
	dir := t.TempDir()
	secretsFile, dbFile := writeSecrets(t, dir, map[string]string{"s1": "true"})
	permissionsFile := filepath.Join(dir, "permissions.json")
	if err := os.WriteFile(permissionsFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "agent.sock")

	var out lockedBuffer
	cmd := exec.Command(os.Args[0], "-S", secretsFile, "-D", dbFile, "-P", permissionsFile, "serve", "-s", socket)
	cmd.Env = append(os.Environ(), "SECRET_AGENT_TEST_CLI=1")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case <-done:
			t.Fatalf("serve exited early: %v\n%s", cmd.ProcessState, &out)
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve never listened\n%s", &out)
		}
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("serve ignored SIGTERM\n%s", &out)
	}
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("serve exit = %v, want terminated by SIGTERM\n%s", cmd.ProcessState, &out)
	}
}

type ptyRun struct {
	cmd    *exec.Cmd
	master *os.File
	out    *lockedBuffer
	done   chan struct{}
}

// startOnPTY runs the CLI with a new pseudo terminal as stdin, stdout, stderr and
// controlling terminal. Everything it writes is collected in out.
func startOnPTY(t *testing.T, args ...string) *ptyRun {
	return startOnPTYEnv(t, []string{"SECRET_AGENT_TEST_CLI=1"}, args...)
}

func startOnPTYEnv(t *testing.T, env []string, args ...string) *ptyRun {
	t.Helper()
	master, slave := openPTY(t)

	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = slave.Close()

	run := &ptyRun{cmd: cmd, master: master, out: &lockedBuffer{}, done: make(chan struct{})}
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(run.out, master); close(copied) }()
	go func() { _ = cmd.Wait(); <-copied; close(run.done) }()
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-run.done:
		case <-time.After(5 * time.Second):
		}
	})
	return run
}

func (r *ptyRun) wait(t *testing.T, timeout time.Duration) syscall.WaitStatus {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(timeout):
		t.Fatalf("CLI still running after %v\n%s", timeout, r.out)
	}
	return r.cmd.ProcessState.Sys().(syscall.WaitStatus)
}

func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	slave, master, err := command.OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	return master, slave
}

func startServe(t *testing.T, secretsFile, dbFile string) string {
	t.Helper()
	dir := t.TempDir()
	permissionsFile := filepath.Join(dir, "permissions.json")
	body := fmt.Sprintf(`{"roles":[{"name":"admin","bindings":[{"auth":"system","uid":%d}],"permissions":{"all":"any"}}]}`, os.Getuid())
	if err := os.WriteFile(permissionsFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "agent.sock")
	var out lockedBuffer
	cmd := exec.Command(os.Args[0], "-S", secretsFile, "-D", dbFile, "-P", permissionsFile, "serve", "-s", socket)
	cmd.Env = append(os.Environ(), "SECRET_AGENT_TEST_CLI=1")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			return socket
		}
		select {
		case <-done:
			t.Fatalf("serve exited early: %v\n%s", cmd.ProcessState, &out)
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve never listened\n%s", &out)
		}
	}
}

func waitOutput(t *testing.T, buf *lockedBuffer, needle string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), needle) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("did not see %q in:\n%s", needle, buf)
}

// writeSecrets writes a secrets config whose create scripts are the given scripts.
func writeSecrets(t *testing.T, dir string, creates map[string]string) (secretsFile, dbFile string) {
	t.Helper()
	var secrets []any
	for id, script := range creates {
		secrets = append(secrets, map[string]any{
			"id":          id,
			"version":     1,
			"environment": map[string]string{"PATH": os.Getenv("PATH")},
			"create":      script,
		})
	}
	data, err := json.Marshal(map[string]any{"secrets": secrets})
	if err != nil {
		t.Fatal(err)
	}
	secretsFile = filepath.Join(dir, "secrets.json")
	if err := os.WriteFile(secretsFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return secretsFile, filepath.Join(dir, "agent.db")
}

func waitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
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
	fields := strings.Fields(string(data[bytes.LastIndexByte(data, ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
