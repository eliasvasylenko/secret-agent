package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

const operationWaitUntilDoneHold = 30 * time.Second

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
	files command.Files,
) (*secrets.Instance, backend.Handle, error) {
	operationId, err := r.postCreate(ctx, name, instanceId, params)
	if err != nil {
		return nil, nil, err
	}

	conns, err := r.attachAll(ctx, operationId, files)
	if err != nil {
		return nil, nil, err
	}
	handle := newRunHandle(r, conns)
	armed := true
	defer func() {
		if armed {
			for _, group := range handle.groups {
				group.close()
			}
		}
	}()

	instance, err := r.postStart(ctx, operationId)
	if err != nil {
		return nil, nil, err
	}

	handle.operationId = operationId
	handle.startPumps()
	handle.startJoin()
	armed = false
	return instance, handle, nil
}

// postCreate records the pending operation and returns its ID.
func (r *httpRunner) postCreate(
	ctx context.Context,
	name secrets.OperationName,
	instanceId string,
	params executor.OperationParameters,
) (string, error) {
	req, err := r.client.buildRequest(ctx, http.MethodPost, "/operations", server.StartOperationRequest{
		SecretId:   r.secretId,
		InstanceId: instanceId,
		Name:       name,
		OperationRequest: server.OperationRequest{
			Env:    params.Env,
			Forced: params.Forced,
			Reason: params.Reason,
		},
	})
	created, err := Do[*server.OperationCreatedResponse](r.client.client, req, err)
	if err != nil {
		return "", err
	}
	return created.OperationID, nil
}

func (r *httpRunner) attachAll(ctx context.Context, operationId string, files command.Files) ([]attached, error) {
	groups, err := fileGroups(files)
	if err != nil {
		return nil, err
	}
	opened := make([]attached, 0, len(groups))
	for _, group := range groups {
		conn, err := openAttach(r.client, ctx, operationId, group)
		if err != nil {
			for _, att := range opened {
				att.close()
			}
			return nil, err
		}
		opened = append(opened, attached{fileGroup: group, conn: conn})
	}
	return opened, nil
}

func (r *httpRunner) postStart(ctx context.Context, operationId string) (*secrets.Instance, error) {
	req, err := r.client.buildRequest(ctx, http.MethodPost, "/operations/"+operationId+"/start", nil)
	return Do[*secrets.Instance](r.client.client, req, err)
}

func (r *httpRunner) getOperation(ctx context.Context, operationId string, untilDone time.Duration) (*server.OperationStatusResponse, error) {
	req, err := r.client.buildRequest(ctx, http.MethodGet, "/operations/"+operationId, nil)
	if err == nil && untilDone > 0 {
		query := req.URL.Query()
		query.Set("untilDone", untilDone.String())
		req.URL.RawQuery = query.Encode()
	}
	return Do[*server.OperationStatusResponse](r.client.client, req, err)
}

func (r *httpRunner) deleteOperation(ctx context.Context, operationId string) error {
	req, err := r.client.buildRequest(ctx, http.MethodDelete, "/operations/"+operationId, nil)
	_, err = Do[struct{}](r.client.client, req, err)
	return err
}

type runHandle struct {
	runner      *httpRunner
	operationId string
	groups      []attached

	pumpWG sync.WaitGroup
	done   chan struct{}

	final   *secrets.Instance
	waitErr error

	joinCtx  context.Context
	stopJoin context.CancelFunc
}

func newRunHandle(runner *httpRunner, groups []attached) *runHandle {
	ctx, cancel := context.WithCancel(context.Background())
	return &runHandle{
		runner:   runner,
		groups:   groups,
		done:     make(chan struct{}),
		joinCtx:  ctx,
		stopJoin: cancel,
	}
}

func (h *runHandle) startPumps() {
	for _, group := range h.groups {
		if group.mode.Writes() {
			// Output is joined. Wait drains it after the process exits.
			if group.mode.Reads() {
				conn, in := group.conn, group.reader()
				go func() { _, _ = io.Copy(conn, in) }()
			}
			out, conn := group.writer(), group.conn
			h.pump(func() error { return copyAttach(out, conn, conn) })
			continue
		}
		if group.mode.Reads() {
			// Input is not joined. The process can exit while this is still open.
			conn, in := group.conn, group.reader()
			go func() { _ = copyAttach(conn, in, conn) }()
		}
	}
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
		defer close(h.done)
		inst, err := h.pollOperation()
		h.pumpWG.Wait()
		h.final = inst
		h.waitErr = err
	}()
}

func (h *runHandle) pollOperation() (*secrets.Instance, error) {
	var inst *secrets.Instance
	for {
		if err := h.joinCtx.Err(); err != nil {
			return inst, err
		}
		status, err := h.runner.getOperation(h.joinCtx, h.operationId, operationWaitUntilDoneHold)
		if err != nil {
			return inst, err
		}
		if status != nil {
			inst = status.Instance
		}
		if inst != nil && inst.Operation.FailedAt != nil {
			return inst, fmt.Errorf("operation failed")
		}
		if inst != nil && inst.Operation.CompletedAt != nil {
			return inst, nil
		}
	}
}

func (h *runHandle) Wait(ctx context.Context) (*secrets.Instance, error) {
	select {
	case <-h.done:
		return h.final, h.waitErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Cancel tears down attach connections. Call at most once.
func (h *runHandle) Cancel(ctx context.Context) error {
	h.stopJoin()
	for _, group := range h.groups {
		group.close()
	}
	_ = h.runner.deleteOperation(ctx, h.operationId)
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ backend.Runner = (*httpRunner)(nil)
var _ backend.Handle = (*runHandle)(nil)
