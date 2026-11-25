package cli

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// TestMain lets tests re-run this test binary as a child process:
//   - SECRET_AGENT_TEST_CLI=1 runs the real CLI with the remaining arguments, as main does.
//   - SECRET_AGENT_TEST_INTERRUPT=1 runs interruptContext and then ignores everything.
func TestMain(m *testing.M) {
	if _, ok := os.LookupEnv("SECRET_AGENT_TEST_FILES"); ok {
		broker, err := command.OpenBroker([]*os.File{os.Stdin, os.Stdout, os.Stderr})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("tty=%d\n", broker.Files().Tty)
		broker.Close()
		os.Exit(0)
	}
	switch {
	case os.Getenv("SECRET_AGENT_TEST_CLI") == "1":
		ctx := context.Background()
		if err := NewCLI(ctx).Run(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case os.Getenv("SECRET_AGENT_TEST_INTERRUPT") == "1":
		ctx, _ := interruptContext(context.Background(), nil)
		fmt.Println("ready")
		<-ctx.Done()
		// Cancellation restores default signal handling from a goroutine. Give it time.
		time.Sleep(100 * time.Millisecond)
		fmt.Println("cancelled")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}
