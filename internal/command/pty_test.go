package command

import (
	"testing"
)

func TestOpenPty(t *testing.T) {
	slave, master, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	if !Terminal(slave) {
		t.Fatal("slave is not a terminal")
	}
	if _, err := master.Write([]byte("x\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	n, err := slave.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 || buf[0] != 'x' {
		t.Fatalf("read %q, want x", buf[:n])
	}
}
