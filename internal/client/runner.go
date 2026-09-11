package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

type httpRunner struct {
	client   *SecretClient
	secretId string
}

func (r *httpRunner) Run(
	ctx context.Context,
	name secrets.OperationName,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, backend.Handle, error) {
	_ = proposer

	conns, err := r.client.attachAll(ctx, r.secretId)
	if err != nil {
		return nil, nil, err
	}

	handle := newRunHandle(r.client, conns)
	armed := true
	defer func() {
		if armed {
			handle.conns.close()
		}
	}()

	instance, err := r.postStart(ctx, name, instanceId, params)
	if err != nil {
		return nil, nil, err
	}

	handle.instanceId = instance.Id
	handle.startPumps(stdio)
	handle.startJoin()
	armed = false
	return instance, handle, nil
}

func (r *httpRunner) postStart(
	ctx context.Context,
	name secrets.OperationName,
	instanceId string,
	params executor.OperationParameters,
) (*secrets.Instance, error) {
	body := server.OperationRequest{
		Env:    params.Env,
		Forced: params.Forced,
		Reason: params.Reason,
	}
	var (
		req *http.Request
		err error
	)
	if name == secrets.Create {
		req, err = BuildRequest(ctx, http.MethodPost, "/instances", server.SecretOperationRequest{
			SecretId:         r.secretId,
			OperationRequest: body,
		})
	} else {
		req, err = BuildRequest(ctx, http.MethodPost, "/operations", server.InstanceOperationRequest{
			InstanceId:       instanceId,
			Name:             name,
			OperationRequest: body,
		})
	}
	return Do[*secrets.Instance](r.client.client, req, err)
}

type runHandle struct {
	client     *SecretClient
	instanceId string
	conns      attachConns

	pumpWG sync.WaitGroup
	done   chan struct{}

	final   *secrets.Instance
	waitErr error
}

func newRunHandle(client *SecretClient, conns attachConns) *runHandle {
	return &runHandle{
		client: client,
		conns:  conns,
		done:   make(chan struct{}),
	}
}

func (h *runHandle) startPumps(stdio command.Stdio) {
	stdin := stdio.Stdin
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	stdout := stdio.Stdout
	if stdout == nil {
		stdout = io.Discard
	}
	stderr := stdio.Stderr
	if stderr == nil {
		stderr = io.Discard
	}

	h.pumpWrite(h.conns.stdin, stdin)
	h.pumpRead(h.conns.stdout, stdout)
	h.pumpRead(h.conns.stderr, stderr)
}

func (h *runHandle) pumpWrite(conn *attachConn, src io.Reader) {
	h.pump(func() error { return copyAttachWrite(conn, src) })
}

func (h *runHandle) pumpRead(conn *attachConn, dst io.Writer) {
	h.pump(func() error { return copyAttachRead(conn, dst) })
}

func (h *runHandle) pump(copyFn func() error) {
	h.pumpWG.Add(1)
	go func() {
		defer h.pumpWG.Done()
		_ = copyFn()
	}()
}

func (h *runHandle) startJoin() {
	go func() {
		h.pumpWG.Wait()
		inst, err := h.client.Catalog().Instances().Get(context.Background(), h.instanceId)
		if err == nil && inst != nil && inst.Status.FailedAt != nil {
			err = fmt.Errorf("operation failed")
		}
		h.final = inst
		h.waitErr = err
		close(h.done)
	}()
}

func (h *runHandle) Wait(ctx context.Context) (*secrets.Instance, error) {
	select {
	case <-h.done:
		return h.final, h.waitErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Cancel tears down attach connections. Like net.Conn.Close, call at most once.
func (h *runHandle) Cancel(ctx context.Context) error {
	h.conns.close()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// attachConns is one attach upgrade per stream, opened before the start POST.
type attachConns struct {
	stdin  *attachConn
	stdout *attachConn
	stderr *attachConn
}

func (a attachConns) close() {
	for _, conn := range []*attachConn{a.stdin, a.stdout, a.stderr} {
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

	attach := func(stream string) (*attachConn, error) {
		return c.upgrade(ctx, "/secrets/"+secretId+"/attach/"+stream)
	}

	var err error
	if conns.stdin, err = attach("stdin"); err != nil {
		return conns, err
	}
	if conns.stdout, err = attach("stdout"); err != nil {
		return conns, err
	}
	if conns.stderr, err = attach("stderr"); err != nil {
		return conns, err
	}

	armed = false
	return conns, nil
}

var _ backend.Runner = (*httpRunner)(nil)
var _ backend.Handle = (*runHandle)(nil)
