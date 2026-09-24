package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const AttachUpgradeProtocol = "secret-agent-process/1"

var errNoAttachSlot = NewErrorResponse(http.StatusNotFound, fmt.Errorf("no attach slot"))

type attachStream string

const (
	attachStreamStdin  attachStream = "stdin"
	attachStreamStdout attachStream = "stdout"
	attachStreamStderr attachStream = "stderr"
)

func parseAttachStream(name string) (attachStream, error) {
	switch attachStream(name) {
	case attachStreamStdin, attachStreamStdout, attachStreamStderr:
		return attachStream(name), nil
	default:
		return "", NewErrorResponse(http.StatusBadRequest, fmt.Errorf("unknown attach stream %q", name))
	}
}

func (s *Controller) attachSecret(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	if !requirePermit(w, r, secretId) {
		return
	}
	stream, err := parseAttachStream(r.PathValue("stream"))
	if err != nil {
		writeError(w, err)
		return
	}

	if !connectionUpgrade(r, AttachUpgradeProtocol) {
		writeError(w, NewErrorResponse(http.StatusUpgradeRequired, fmt.Errorf("connection upgrade required")))
		return
	}

	identity := identityFromContext(r.Context())
	if identity == nil {
		writeError(w, NewErrorResponse(http.StatusUnauthorized, fmt.Errorf("identity not found in context")))
		return
	}

	slot, err := s.claimSlot(secretId, identity.Principal, stream)
	if err != nil {
		writeError(w, err)
		return
	}

	armed := true
	defer func() {
		if armed {
			s.closeSlot(slot)
		}
	}()

	var bodyPrefix []byte
	if stream == attachStreamStdin && r.Body != nil {
		bodyPrefix, err = io.ReadAll(r.Body)
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusBadRequest, err))
			return
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		writeError(w, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("response writer does not support hijacking")))
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		writeError(w, NewErrorResponse(http.StatusInternalServerError, err))
		return
	}
	defer conn.Close()

	if _, err := bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + AttachUpgradeProtocol + "\r\n\r\n"); err != nil {
		return
	}
	if err := bufrw.Flush(); err != nil {
		return
	}

	armed = false
	s.attachFinished(slot, stream, slot.serveAttach(slot.ctx, stream, bodyPrefix, conn))
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

func (slot *attachSlot) serveAttach(ctx context.Context, stream attachStream, bodyPrefix []byte, conn net.Conn) error {
	switch stream {
	case attachStreamStdin:
		defer slot.pipes.stdinW.Close()
		if len(bodyPrefix) > 0 {
			if _, err := slot.pipes.stdinW.Write(bodyPrefix); err != nil {
				return err
			}
		}
		_, err := copyWithContext(ctx, slot.pipes.stdinW, conn)
		return err
	case attachStreamStdout:
		_, err := copyWithContext(ctx, conn, slot.pipes.stdoutR)
		return err
	case attachStreamStderr:
		_, err := copyWithContext(ctx, conn, slot.pipes.stderrR)
		return err
	default:
		return fmt.Errorf("unknown attach stream %q", stream)
	}
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := io.Copy(dst, src)
		done <- result{n: n, err: err}
	}()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case res := <-done:
		return res.n, res.err
	}
}
