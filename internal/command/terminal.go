package command

import (
	"os"

	"golang.org/x/sys/unix"
)

// Terminal reports whether f is a terminal.
func Terminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

// ControllingTerminal reports whether f is this process's controlling
// terminal. That is session state, so this checks TIOCGSID, not /dev/tty.
func ControllingTerminal(f *os.File) bool {
	sid, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGSID)
	if err != nil {
		return false
	}
	self, err := unix.Getsid(0)
	return err == nil && sid == self
}
