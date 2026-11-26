//go:build linux

package command

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetRaw(t *testing.T) {
	slave, master, err := OpenPty()
	if err != nil {
		t.Skipf("no pseudo terminals: %v", err)
	}
	defer master.Close()
	defer slave.Close()

	restore, err := setRaw(slave)
	if err != nil {
		t.Fatal(err)
	}
	defer restore()

	ti, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if ti.Lflag&unix.ISIG == 0 {
		t.Fatal("ISIG was turned off")
	}
	if ti.Lflag&unix.ECHO != 0 {
		t.Fatal("ECHO is still on")
	}
	if ti.Lflag&unix.ICANON != 0 {
		t.Fatal("ICANON is still on")
	}
}
