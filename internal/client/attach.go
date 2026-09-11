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
	armed := true
	defer func() {
		if armed {
			_ = conn.Close()
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", server.AttachUpgradeProtocol)
	if err := req.Write(conn); err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, err
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("attach upgrade: status %d", response.StatusCode)
	}

	armed = false
	return &attachConn{Conn: conn, reader: reader}, nil
}

func copyAttachWrite(conn *attachConn, src io.Reader) error {
	defer conn.Close()
	_, err := io.Copy(conn, src)
	return ignoreClosedPipe(err)
}

func copyAttachRead(conn *attachConn, dst io.Writer) error {
	defer conn.Close()
	_, err := io.Copy(dst, conn)
	return ignoreClosedPipe(err)
}

func ignoreClosedPipe(err error) error {
	if err != nil && !isClosedPipe(err) {
		return err
	}
	return nil
}

func isClosedPipe(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "closed pipe") ||
		strings.Contains(err.Error(), "use of closed network connection") ||
		err == io.EOF
}
