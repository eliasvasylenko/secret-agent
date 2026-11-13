package command

import (
	"os"
)

// NoTty means no controlling terminal.
const NoTty = -1

// Files is what a process starts with. Fds is indexed by descriptor.
// The same *os.File twice is one open file. Nil means nothing there.
// Tty is the descriptor to install as the controlling terminal, or NoTty.
type Files struct {
	Fds []*os.File
	Tty int
}

func (f Files) file(fd int) *os.File {
	if fd < 0 || fd >= len(f.Fds) {
		return nil
	}
	return f.Fds[fd]
}

// FileMode is r, w, tty, or ctty. tty is a terminal. ctty is the
// controlling terminal. The client chooses this. Unknown modes are
// rejected; a later kind (seekable file, duplex fifo) is a new value
// and a new attachment, not a change to these four.
type FileMode string

const (
	Read  FileMode = "r"
	Write FileMode = "w"
	Tty   FileMode = "tty"
	Ctty  FileMode = "ctty"
)

func (m FileMode) Valid() bool {
	switch m {
	case Read, Write, Tty, Ctty:
		return true
	}
	return false
}

func (m FileMode) Reads() bool {
	switch m {
	case Read, Tty, Ctty:
		return true
	}
	return false
}

func (m FileMode) Writes() bool {
	switch m {
	case Write, Tty, Ctty:
		return true
	}
	return false
}

func (m FileMode) Terminal() bool { return m == Tty || m == Ctty }

// MaxFd is the highest descriptor number we accept.
const MaxFd = 1023
