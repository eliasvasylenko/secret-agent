package cli

import (
	"fmt"
	"io"
	"net"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/dialstdio"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

func runDialStdio(socket, user, header string, in io.Reader, out io.Writer) error {
	if socket == "" {
		socket = server.DefaultSocket
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("dial-stdio: %w", err)
	}
	if user != "" {
		in, err = auth.InjectForwardedUser(conn, in, user, header)
		if err != nil {
			_ = conn.Close()
			return err
		}
	}
	return dialstdio.Proxy(conn, in, out)
}
