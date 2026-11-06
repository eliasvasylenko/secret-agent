package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"golang.org/x/sys/unix"
)

const AttachUpgradeProtocol = "secret-agent-process/1"

// attachment is one open file for one or more descriptors, and the other
// end of that file, which is the attached connection. r and w are pipes.
// tty and ctty are a pty. ctty is also the controlling terminal.
type attachment struct {
	fds  []int
	mode command.FileMode

	// process is dup'd onto each claimed process descriptor.
	// peer is the end served to the attached connection.
	process *os.File
	peer    *os.File
}

func newAttachment(fds []int, mode command.FileMode) (*attachment, error) {
	a := &attachment{fds: fds, mode: mode}
	var err error
	switch mode {
	case command.Tty, command.Ctty:
		a.process, a.peer, err = openTerminal()
	case command.Read:
		a.process, a.peer, err = os.Pipe()
	case command.Write:
		a.peer, a.process, err = os.Pipe()
	default:
		return nil, fmt.Errorf("unknown attach mode %q", mode)
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (a *attachment) close() {
	if a.peer != nil {
		_ = a.peer.Close()
	}
	if a.process != nil {
		_ = a.process.Close()
	}
}

// serve copies bytes until one side finishes. For a read pipe, client EOF
// closes the write end. A terminal is copied both ways, and client EOF
// leaves the master open so the process can still write.
func (a *attachment) serve(conn io.ReadWriter) {
	if a.mode.Terminal() {
		done := make(chan struct{})
		go func() {
			_, _ = io.Copy(a.peer, conn)
			close(done)
		}()
		_, _ = io.Copy(conn, a.peer)
		<-done
		return
	}
	if a.mode.Reads() {
		defer a.peer.Close()
		_, _ = io.Copy(a.peer, conn)
		return
	}
	_, _ = io.Copy(conn, a.peer)
}

func openTerminal() (slave, master *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			_ = master.Close()
		}
	}()
	if err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		return nil, nil, err
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return slave, master, nil
}

func (s *Controller) attachOperation(w http.ResponseWriter, r *http.Request) {
	if !connectionUpgrade(r, AttachUpgradeProtocol) {
		writeError(w, NewErrorResponse(http.StatusUpgradeRequired, fmt.Errorf("connection upgrade required")))
		return
	}

	var request AttachRequest
	if err := readBody(r, &request); err != nil {
		writeError(w, err)
		return
	}
	if err := request.Validate(); err != nil {
		writeError(w, NewErrorResponse(http.StatusBadRequest, err))
		return
	}

	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}

	entry, err := s.operations.get(r.PathValue("operationId"))
	if err != nil {
		writeError(w, err)
		return
	}
	att, err := entry.claimAttach(identity.Principal.GetName(), request.Fds, request.Mode)
	if err != nil {
		writeError(w, err)
		return
	}

	conn, err := upgradeConnection(w, r)
	if err != nil {
		_ = s.operations.cancel(entry)
		writeError(w, err)
		return
	}
	defer conn.Close()
	// Close the connection when the run is cancelled or finishes, so serve
	// unblocks.
	defer context.AfterFunc(entry.ctx, func() { _ = conn.Close() })()

	att.serve(conn)
	s.operations.attachEnded(entry, att)
}

// attachConn reads through the hijack buffer, so bytes sent ahead of the
// 101 are not dropped.
type attachConn struct {
	io.Reader
	net.Conn
}

func (c attachConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }

// upgradeConnection hijacks the request and writes the 101. The body was
// the attach claim. Bytes after the 101 are the file.
func upgradeConnection(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("response writer does not support hijacking"))
	}
	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		return nil, NewErrorResponse(http.StatusInternalServerError, err)
	}

	if _, err := bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + AttachUpgradeProtocol + "\r\n\r\n"); err != nil {
		_ = conn.Close()
		return nil, NewErrorResponse(http.StatusInternalServerError, err)
	}
	if err := bufrw.Flush(); err != nil {
		_ = conn.Close()
		return nil, NewErrorResponse(http.StatusInternalServerError, err)
	}

	return attachConn{Reader: bufrw.Reader, Conn: conn}, nil
}

func connectionUpgrade(r *http.Request, protocol string) bool {
	if !headerContainsToken(r.Header.Values("Connection"), "upgrade") {
		return false
	}
	return headerContainsToken(r.Header.Values("Upgrade"), protocol)
}

func headerContainsToken(values []string, token string) bool {
	for _, value := range values {
		for _, part := range splitHeaderList(value) {
			if strings.EqualFold(part, token) {
				return true
			}
		}
	}
	return false
}

func splitHeaderList(value string) []string {
	var parts []string
	for _, segment := range strings.Split(value, ",") {
		part := strings.TrimSpace(segment)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}
