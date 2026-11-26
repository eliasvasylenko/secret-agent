package command

import (
	"os"
	"path/filepath"
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

func TestLocalMode_readWriteFifoIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	_, err = LocalMode(f)
	if err == nil || err.Error() != "read-write file cannot be attached" {
		t.Fatalf("LocalMode error = %v", err)
	}
}
