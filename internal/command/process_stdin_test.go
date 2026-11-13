package command

import (
	"context"
	"os"
	"testing"
	"time"
)

func devNull(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestProcess_returnsWhenChildExitsWithoutReadingStdin(t *testing.T) {
	out := t.TempDir() + "/out"
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close() // stdin stays open and unread for the whole run

	files := Files{Fds: []*os.File{r, devNull(t), devNull(t)}, Tty: NoTty}
	cmd := New("echo ok > "+out, nil, "")

	done := make(chan error, 1)
	go func() { done <- cmd.Process(context.Background(), files, Environment{}) }()

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
			t.Fatalf("file = %q, want ok\n", data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Process did not return after child exited")
	}
}

func TestProcess_stillStreamsStdinWhileChildRuns(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("payload\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	files := Files{Fds: []*os.File{r, devNull(t), devNull(t)}, Tty: NoTty}
	cmd := New(`read -r line; test "$line" = payload`, nil, "")
	if err := cmd.Process(context.Background(), files, Environment{}); err != nil {
		t.Fatalf("Process: %v", err)
	}
}

func TestProcess_extraFileDescriptor(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err := w.WriteString("payload\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	files := Files{Fds: []*os.File{devNull(t), devNull(t), devNull(t), nil, nil, r}, Tty: NoTty}
	cmd := New(`read -r line <&5; test "$line" = payload`, nil, "")
	if err := cmd.Process(context.Background(), files, Environment{}); err != nil {
		t.Fatalf("Process: %v", err)
	}
}
