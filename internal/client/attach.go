package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/eliasvasylenko/secret-agent/internal/server"
)

func (c *SecretClient) upgrade(ctx context.Context, path string) (io.ReadWriteCloser, error) {
	if c.attach != nil {
		return c.attach(ctx, path)
	}

	req, err := c.buildRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", server.AttachUpgradeProtocol)

	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		defer response.Body.Close()
		return nil, fmt.Errorf("attach upgrade: status %d", response.StatusCode)
	}
	conn, ok := response.Body.(io.ReadWriteCloser)
	if !ok {
		_ = response.Body.Close()
		return nil, fmt.Errorf("attach upgrade: response body is not writable")
	}
	return conn, nil
}

func copyAttach(dst io.Writer, src io.Reader, conn io.Closer) error {
	defer conn.Close()
	_, err := io.Copy(dst, src)
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

// attachConns is one attach upgrade per stream, opened before the start POST.
type attachConns struct {
	stdin  io.ReadWriteCloser
	stdout io.ReadWriteCloser
	stderr io.ReadWriteCloser
}

func (a attachConns) close() {
	for _, conn := range []io.ReadWriteCloser{a.stdin, a.stdout, a.stderr} {
		if conn != nil {
			_ = conn.Close()
		}
	}
}

func (c *SecretClient) attachAll(ctx context.Context, secretId string) (attachConns, error) {
	var conns attachConns
	armed := true
	defer func() {
		if armed {
			conns.close()
		}
	}()

	var err error
	if conns.stdin, err = c.upgrade(ctx, "/secrets/"+secretId+"/attach/stdin"); err != nil {
		return conns, err
	}
	if conns.stdout, err = c.upgrade(ctx, "/secrets/"+secretId+"/attach/stdout"); err != nil {
		return conns, err
	}
	if conns.stderr, err = c.upgrade(ctx, "/secrets/"+secretId+"/attach/stderr"); err != nil {
		return conns, err
	}

	armed = false
	return conns, nil
}
