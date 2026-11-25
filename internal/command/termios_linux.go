//go:build linux

package command

import (
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// setRaw puts f in raw mode but leaves ISIG on, so Ctrl-C still signals
// this process. Restore the previous state with the returned func.
func setRaw(f *os.File) (func(), error) {
	fd := int(f.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		_ = term.Restore(fd, state)
		return nil, err
	}
	termios.Lflag |= unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		_ = term.Restore(fd, state)
		return nil, err
	}
	return func() { _ = term.Restore(fd, state) }, nil
}
