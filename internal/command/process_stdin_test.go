package command

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

type blockReader struct{}

func (blockReader) Read([]byte) (int, error) {
	select {}
}

func TestProcess_returnsWhenChildExitsWithoutReadingStdin(t *testing.T) {
	out := t.TempDir() + "/out"
	stdio := Stdio{Stdin: blockReader{}, Stdout: io.Discard, Stderr: io.Discard}
	cmd := New("echo ok > "+out, nil, "")

	done := make(chan error, 1)
	go func() { done <- cmd.Process(context.Background(), stdio, Environment{}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(data) != "ok\n" {
			t.Fatalf("file = %q, want ok\\n", data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Process did not return after child exited")
	}
}

func TestProcess_stillStreamsStdinWhileChildRuns(t *testing.T) {
	stdio := Stdio{
		Stdin:  strings.NewReader("payload\n"),
		Stdout: io.Discard,
		Stderr: io.Discard,
	}
	cmd := New(`read -r line; test "$line" = payload`, nil, "")
	if err := cmd.Process(context.Background(), stdio, Environment{}); err != nil {
		t.Fatalf("Process: %v", err)
	}
}
