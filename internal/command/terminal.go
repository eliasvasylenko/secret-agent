package command

import (
	"fmt"
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

// LocalMode is r, w, or tty. O_RDWR is not a stream, so that is an error.
// ctty comes from Files.Tty, not from here.
func LocalMode(f *os.File) (FileMode, error) {
	if Terminal(f) {
		return Tty, nil
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return "", err
	}
	switch flags & unix.O_ACCMODE {
	case unix.O_WRONLY:
		return Write, nil
	case unix.O_RDONLY:
		return Read, nil
	default:
		return "", fmt.Errorf("file is not a stream")
	}
}
