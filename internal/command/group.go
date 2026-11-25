package command

import (
	"fmt"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

// FileGroup is one open file and every descriptor that refers to it.
type FileGroup struct {
	Fds  []int
	Mode FileMode
	File *os.File
}

// FileGroups is the attach list: one FileGroup per open file.
type FileGroups []FileGroup

// GroupFiles groups a dup into one FileGroup and leaves a second open as
// its own. Nil slots are skipped. A read-write file is an error.
// Files.Tty turns a tty group into ctty.
func GroupFiles(files Files) (FileGroups, error) {
	groups, err := groupByOpenFile(files.Fds)
	if err != nil {
		return nil, err
	}
	for i := range groups {
		mode, err := LocalMode(groups[i].File)
		if err != nil {
			return nil, fmt.Errorf("fd %d: %w", minFd(groups[i].Fds), err)
		}
		if files.Tty != NoTty && slices.Contains(groups[i].Fds, files.Tty) && mode == Tty {
			mode = Ctty
		}
		groups[i].Mode = mode
	}
	return groups, nil
}

func groupByOpenFile(fds []*os.File) (FileGroups, error) {
	var entries []fdFile
	for fd, file := range fds {
		if file != nil {
			entries = append(entries, fdFile{fd: fd, file: file})
		}
	}
	if err := sortByOpenFile(entries); err != nil {
		return nil, err
	}

	var groups FileGroups
	for i, entry := range entries {
		if i > 0 {
			cmp, err := compareOpenFiles(entries[i-1].file, entry.file)
			if err != nil {
				return nil, fmt.Errorf("fd %d: %w", entry.fd, err)
			}
			if cmp == 0 {
				group := &groups[len(groups)-1]
				group.Fds = append(group.Fds, entry.fd)
				continue
			}
		}
		groups = append(groups, FileGroup{Fds: []int{entry.fd}, File: entry.file})
	}
	return groups, nil
}

func (g FileGroups) Files() Files {
	last := -1
	tty := NoTty
	for _, group := range g {
		for _, fd := range group.Fds {
			if fd > last {
				last = fd
			}
		}
		if group.Mode == Ctty && len(group.Fds) > 0 {
			fd := minFd(group.Fds)
			if tty == NoTty || fd < tty {
				tty = fd
			}
		}
	}
	files := Files{Tty: tty}
	if last < 0 {
		return files
	}
	files.Fds = make([]*os.File, last+1)
	for _, group := range g {
		for _, fd := range group.Fds {
			if fd >= 0 {
				files.Fds[fd] = group.File
			}
		}
	}
	return files
}

func minFd(fds []int) int {
	m := fds[0]
	for _, fd := range fds[1:] {
		if fd < m {
			m = fd
		}
	}
	return m
}

type fdFile struct {
	fd   int
	file *os.File
}

// sortByOpenFile orders entries so a dup sits next to its original.
func sortByOpenFile(entries []fdFile) error {
	var sortErr error
	slices.SortFunc(entries, func(a, b fdFile) int {
		if sortErr != nil {
			return 0
		}
		cmp, err := compareOpenFiles(a.file, b.file)
		if err != nil {
			sortErr = fmt.Errorf("fd %d: %w", b.fd, err)
			return 0
		}
		return cmp
	})
	return sortErr
}

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
