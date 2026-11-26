package client

import (
	"context"
	"errors"
	"io"
	"net"
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

// attached is one FileGroup plus the connection for it.
type attached struct {
	command.FileGroup
	conn io.ReadWriteCloser
}

func (a attached) close() {
	if a.conn != nil {
		_ = a.conn.Close()
	}
}

func attachRequest(group command.FileGroup) server.AttachRequest {
	return server.AttachRequest{Fds: group.Fds, Mode: group.Mode}
}

// openAttach dials one attach. Tests replace it.
var openAttach = func(c *SecretClient, ctx context.Context, operationId string, group command.FileGroup) (io.ReadWriteCloser, error) {
	return c.upgrade(ctx, "/operations/"+operationId+"/attach", attachRequest(group))
}
