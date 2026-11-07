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

// LocalMode is r, w, or tty. ctty comes from Files.Tty, not from here.
// A regular file opened read-write is refused: its writes share an offset
// with its reads, and a pipe would drop them. A fifo opened read-write is
// read. The shell uses that so the open does not block, and so a read waits
// for a writer instead of seeing EOF.
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
	}
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeNamedPipe != 0 {
		return Read, nil
	}
	return "", fmt.Errorf("read-write file cannot be attached")
}
