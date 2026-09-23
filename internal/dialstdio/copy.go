package dialstdio

import (
	"fmt"
	"io"
	"net"
)

// Copy dials a Unix socket and proxies in/out, like Docker's `system dial-stdio`.
func Copy(socket string, in io.Reader, out io.Writer) error {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return fmt.Errorf("dial-stdio: %w", err)
	}
	return Proxy(conn, in, out)
}

// Proxy copies bytes bidirectionally between in/out and an established conn.
func Proxy(conn net.Conn, in io.Reader, out io.Writer) error {
	defer conn.Close()
	return bidir(conn, in, out)
}

func bidir(conn net.Conn, in io.Reader, out io.Writer) error {
	readIn := make(chan error, 1)
	writeOut := make(chan error, 1)
	go func() {
		_, err := io.Copy(conn, in)
		closeConnWrite(conn)
		readIn <- err
	}()
	go func() {
		_, err := io.Copy(out, conn)
		writeOut <- err
	}()

	var err error
	select {
	case err = <-readIn:
		if err != nil && err != io.EOF {
			return err
		}
		err = <-writeOut
	case err = <-writeOut:
		// Response finished; stdin may never EOF (SSH). Close the unix conn
		// so later writes fail. Do not wait for readIn: Copy is often blocked
		// on in.Read, and closing conn does not unblock that.
		_ = conn.Close()
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

func closeConnWrite(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}
}
