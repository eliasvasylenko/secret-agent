package command

import (
	"os"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

// OpenPty returns a new pseudo terminal. slave is the terminal the process
// sees; master is the other end. Both are close-on-exec.
func OpenPty() (slave, master *os.File, err error) {
	master, slave, err = pty.Open()
	if err != nil {
		return nil, nil, err
	}
	unix.CloseOnExec(int(master.Fd()))
	unix.CloseOnExec(int(slave.Fd()))
	return slave, master, nil
}
