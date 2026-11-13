package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"syscall"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

func copyAttach(dst io.Writer, src io.Reader, conn io.Closer) error {
	defer conn.Close()
	_, err := io.Copy(dst, src)
	if err != nil && isClosedPipe(err) {
		err = nil
	}
	return err
}

func isClosedPipe(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE)
}

// fileGroup is one attach before it is dialed: the descriptors, the mode,
// and the local file.
type fileGroup struct {
	fds  []int
	mode command.FileMode
	file *os.File
}

// attached is a fileGroup plus the connection for it.
type attached struct {
	fileGroup
	conn io.ReadWriteCloser
}

func (a attached) close() {
	if a.conn != nil {
		_ = a.conn.Close()
	}
}

func (g fileGroup) reader() io.Reader {
	if g.file == nil {
		return nil
	}
	return g.file
}

func (g fileGroup) writer() io.Writer {
	if g.file == nil {
		return nil
	}
	return g.file
}

func attachRequest(group fileGroup) server.AttachRequest {
	return server.AttachRequest{Fds: group.fds, Mode: group.mode}
}

// openAttach dials one attach. Tests replace it.
var openAttach = func(c *SecretClient, ctx context.Context, operationId string, group fileGroup) (io.ReadWriteCloser, error) {
	return c.upgrade(ctx, "/operations/"+operationId+"/attach", attachRequest(group))
}

// fileGroups groups a dup into one attach and leaves a second open as its
// own. Nil slots are skipped. A read-write file is an error.
// Files.Tty turns a tty group into ctty.
func fileGroups(files command.Files) ([]fileGroup, error) {
	var entries []fdFile
	for fd, file := range files.Fds {
		if file != nil {
			entries = append(entries, fdFile{fd: fd, file: file})
		}
	}
	if err := sortByOpenFile(entries); err != nil {
		return nil, err
	}

	var groups []fileGroup
	for i, entry := range entries {
		if i > 0 {
			cmp, err := compareOpenFiles(entries[i-1].file, entry.file)
			if err != nil {
				return nil, fmt.Errorf("fd %d: %w", entry.fd, err)
			}
			if cmp == 0 {
				group := &groups[len(groups)-1]
				group.fds = append(group.fds, entry.fd)
				if entry.fd == files.Tty && group.mode == command.Tty {
					group.mode = command.Ctty
				}
				continue
			}
		}
		mode, err := command.LocalMode(entry.file)
		if err != nil {
			return nil, fmt.Errorf("fd %d: %w", entry.fd, err)
		}
		if entry.fd == files.Tty && mode == command.Tty {
			mode = command.Ctty
		}
		groups = append(groups, fileGroup{fds: []int{entry.fd}, mode: mode, file: entry.file})
	}
	return groups, nil
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
