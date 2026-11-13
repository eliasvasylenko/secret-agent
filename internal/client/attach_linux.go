//go:build linux

package client

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// kcmpFile is KCMP_FILE.
const kcmpFile = 0

// compareOpenFiles orders a and b by open file description.
// -1, 0, or 1, same as cmp.Compare.
func compareOpenFiles(a, b *os.File) (int, error) {
	if a == b {
		return 0, nil
	}
	res, _, errno := unix.Syscall6(unix.SYS_KCMP,
		uintptr(os.Getpid()), uintptr(os.Getpid()),
		kcmpFile, uintptr(a.Fd()), uintptr(b.Fd()), 0)
	if errno != 0 {
		return 0, errno
	}
	switch res {
	case 0:
		return 0, nil
	case 1:
		return -1, nil
	case 2:
		return 1, nil
	default:
		return 0, fmt.Errorf("kcmp returned %d", res)
	}
}
