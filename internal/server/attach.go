package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
)

const AttachUpgradeProtocol = "secret-agent-process/1"

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

func (s *Controller) attachProcess(w http.ResponseWriter, r *http.Request) {
	secretId := r.PathValue("secretId")
	instanceId := r.PathValue("instanceId")
	opNumber, err := parsePath(r, "opNumber", strconv.Atoi)
	if err != nil {
		writeError(w, err)
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
		writeError(w, NewErrorResponse(http.StatusInternalServerError, fmt.Errorf("identity not found in context")))
		return
	}

	key := operationMapKey{secretId: secretId, instanceId: instanceId, operationNumber: opNumber}
	load, ok := s.operations.Load(key)
	if !ok {
		writeError(w, NewErrorResponse(http.StatusNotFound, fmt.Errorf("operation %d not found", opNumber)))
		return
	}
	op := load.(*operation)
	if identity.Principal != op.startedBy {
		writeError(w, NewErrorResponse(http.StatusForbidden, fmt.Errorf("operation %d was started by a different principal", opNumber)))
		return
	}
	if err := op.claimAttach(stream); err != nil {
		writeError(w, err)
		return
	}

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

	if _, err := bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + AttachUpgradeProtocol + "\r\n\r\n"); err != nil {
		conn.Close()
		return
	}
	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return
	}

	if err := op.serveAttach(r.Context(), stream, bodyPrefix, conn); err != nil {
		conn.Close()
	}
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

func (op *operation) claimAttach(stream attachStream) error {
	op.attachMu.Lock()
	defer op.attachMu.Unlock()

	var claimed *bool
	switch stream {
	case attachStreamStdin:
		claimed = &op.stdinAttached
	case attachStreamStdout:
		claimed = &op.stdoutAttached
	case attachStreamStderr:
		claimed = &op.stderrAttached
	default:
		return fmt.Errorf("unknown attach stream %q", stream)
	}
	if *claimed {
		return NewErrorResponse(http.StatusConflict, fmt.Errorf("%s already attached", stream))
	}
	*claimed = true
	return nil
}

func (op *operation) serveAttach(ctx context.Context, stream attachStream, bodyPrefix []byte, conn net.Conn) error {
	switch stream {
	case attachStreamStdin:
		defer op.pipes.stdinW.Close()
		if len(bodyPrefix) > 0 {
			if _, err := op.pipes.stdinW.Write(bodyPrefix); err != nil {
				return err
			}
		}
		_, err := copyWithContext(ctx, op.pipes.stdinW, conn)
		return err
	case attachStreamStdout:
		_, err := copyWithContext(ctx, conn, op.pipes.stdoutR)
		return err
	case attachStreamStderr:
		_, err := copyWithContext(ctx, conn, op.pipes.stderrR)
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
