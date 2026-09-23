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
		req, err = r.client.buildRequest(ctx, http.MethodPost, "/instances", server.SecretOperationRequest{
			SecretId:         r.secretId,
			OperationRequest: body,
		})
	} else {
		req, err = r.client.buildRequest(ctx, http.MethodPost, "/operations", server.InstanceOperationRequest{
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

	// Stdin is forwarded but not joined. A process can exit without reading
	// it; waiting for stdin EOF would hang a CLI whose stdin is still open.
	go func() { _ = copyAttach(h.conns.stdin, stdin, h.conns.stdin) }()
	h.pump(func() error { return copyAttach(stdout, h.conns.stdout, h.conns.stdout) })
	h.pump(func() error { return copyAttach(stderr, h.conns.stderr, h.conns.stderr) })
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
		if h.conns.stdin != nil {
			_ = h.conns.stdin.Close()
		}
		inst, err := h.client.Catalog().Instances().Get(context.Background(), h.instanceId)
		if err == nil && inst != nil {
			switch {
			case inst.Status.FailedAt != nil:
				err = fmt.Errorf("operation failed")
			case inst.Status.CompletedAt == nil:
				err = fmt.Errorf("operation not completed")
			}
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

var _ backend.Runner = (*httpRunner)(nil)
var _ backend.Handle = (*runHandle)(nil)
