package cli

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The first signal cancels. The second terminates the process, so a stalled cancellation
// cannot trap the operator.
func TestInterruptContext_secondSignalTerminates(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "SECRET_AGENT_TEST_INTERRUPT=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(10*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	out := bufio.NewReader(stdout)
	expectLine := func(want string) {
		t.Helper()
		line, err := out.ReadString('\n')
		if err != nil || strings.TrimSpace(line) != want {
			t.Fatalf("child said %q (%v), want %q", line, err, want)
		}
	}

	expectLine("ready")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	expectLine("cancelled")
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	_ = cmd.Wait()
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != syscall.SIGTERM {
		t.Fatalf("child exit = %v, want terminated by SIGTERM", cmd.ProcessState)
	}
}

func TestInterruptContext_cancelledBySignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, stop := interruptContext(context.Background(), nil)
			defer stop()

			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("context was not cancelled by the signal")
			}
		})
	}
}
