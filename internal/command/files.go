package command

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// errReadWriteFile is a duplex non-terminal. It is not an attachable mode
// and not an I/O failure, so the broker can leave the file unchanged.
var errReadWriteFile = errors.New("read-write file cannot be attached")

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

// LocalMode is r, w, or tty. ctty comes from Files.Tty, not from here.
// A read-write open is refused: a pipe is one direction, and a regular
// file's reads and writes share an offset. Open the file read-only or
// write-only, or use a terminal.
func LocalMode(f *os.File) (FileMode, error) {
	if Terminal(f) {
		return Tty, nil
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return "", err
	}
	switch flags & unix.O_ACCMODE {
	case unix.O_RDONLY:
		return Read, nil
	case unix.O_WRONLY:
		return Write, nil
	default:
		return "", errReadWriteFile
	}
}

// MaxFd is the highest descriptor number we accept.
const MaxFd = 1023
