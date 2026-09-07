package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/eliasvasylenko/secret-agent/internal/server"
)

type attachConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *attachConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func upgradeAttach(ctx context.Context, socket, path string) (*attachConn, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}

	request := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: unix\r\nConnection: Upgrade\r\nUpgrade: %s\r\nContent-Length: 0\r\n\r\n",
		path,
		server.AttachUpgradeProtocol,
	)
	if _, err := conn.Write([]byte(request)); err != nil {
		conn.Close()
		return nil, err
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if response.Body != nil {
		response.Body.Close()
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("attach upgrade: status %d", response.StatusCode)
	}

	return &attachConn{Conn: conn, reader: reader}, nil
}

func copyAttach(ctx context.Context, conn *attachConn, direction attachDirection, stream io.ReadWriter) error {
	done := make(chan error, 1)
	go func() {
		var err error
		switch direction {
		case attachWrite:
			_, err = io.Copy(conn, stream)
		case attachRead:
			_, err = io.Copy(stream, conn)
		}
		conn.Close()
		done <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil && !isClosedPipe(err) {
			return err
		}
		return nil
	}
}

type attachDirection int

const (
	attachWrite attachDirection = iota
	attachRead
)

func isClosedPipe(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "closed pipe") ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		err == io.EOF
}
