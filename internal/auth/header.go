package auth

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
)

// DefaultAssertHeader is the header an assert authenticator reads when it does not set one.
const DefaultAssertHeader = "X-Secret-Agent-User"

// InjectAssertedUser reads the HTTP request from in, sets header to user,
// writes it to conn, and returns any unread bytes from in for the rest of the
// connection (including attach after 101). Empty header means DefaultAssertHeader.
func InjectAssertedUser(conn net.Conn, in io.Reader, user, header string) (io.Reader, error) {
	if header == "" {
		header = DefaultAssertHeader
	}
	br := bufio.NewReader(in)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("assert header: read request: %w", err)
	}
	req.Header.Del(header)
	req.Header.Set(header, user)
	err = req.Write(conn)
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("assert header: write request: %w", err)
	}
	return br, nil
}
