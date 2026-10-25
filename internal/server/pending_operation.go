package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

var errNoPendingOperation = NewErrorResponse(http.StatusNotFound, fmt.Errorf("no such operation"))

var pendingOperationTTL = 10 * time.Minute

type pendingState string

const (
	pendingStatePending   pendingState = "pending"
	pendingStateStarted   pendingState = "started"
	pendingStateCompleted pendingState = "completed"
	pendingStateFailed    pendingState = "failed"
)

// pendingOperation is an operation created before it starts. It owns the attach
// streams, succeeding the (secret, principal) attach slot.
type pendingOperation struct {
	id         string
	creator    string
	secretId   string
	instanceId string
	name       secrets.OperationName
	params     executor.OperationParameters
	expiresAt  time.Time

	pipes  *attachPipes
	ctx    context.Context
	cancel context.CancelFunc

	claimed  map[attachStream]bool
	state    pendingState
	instance *secrets.Instance
}

func newPendingOperation(creator, secretId, instanceId string, name secrets.OperationName, params executor.OperationParameters) *pendingOperation {
	ctx, cancel := context.WithCancel(context.Background())
	return &pendingOperation{
		id:         newOperationID(),
		creator:    creator,
		secretId:   secretId,
		instanceId: instanceId,
		name:       name,
		params:     params,
		expiresAt:  time.Now().Add(pendingOperationTTL),
		pipes:      newAttachPipes(),
		ctx:        ctx,
		cancel:     cancel,
		claimed:    make(map[attachStream]bool, 3),
		state:      pendingStatePending,
	}
}

func newOperationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// claim is called with Controller.pendingMu held.
func (op *pendingOperation) claim(stream attachStream) error {
	if op.state != pendingStatePending {
		return NewErrorResponse(http.StatusConflict, fmt.Errorf("operation already %s", op.state))
	}
	if op.claimed[stream] {
		return NewErrorResponse(http.StatusConflict, fmt.Errorf("%s already attached", stream))
	}
	op.claimed[stream] = true
	return nil
}

func (op *pendingOperation) close() {
	op.cancel()
	closeAttachPipes(op.pipes)
}

func (op *pendingOperation) watch(c *Controller, handle backend.Handle) {
	go func() {
		final, err := handle.Wait(op.ctx)
		if op.ctx.Err() != nil {
			_ = handle.Cancel(context.Background())
			final, err = handle.Wait(context.Background())
		}
		c.pendingMu.Lock()
		op.instance = final
		if err != nil {
			op.state = pendingStateFailed
		} else {
			op.state = pendingStateCompleted
		}
		c.pendingMu.Unlock()
		op.close()
	}()
}

func (op *pendingOperation) snapshot() OperationStatusResponse {
	return OperationStatusResponse{
		OperationID: op.id,
		State:       string(op.state),
		SecretID:    op.secretId,
		InstanceID:  op.instanceId,
		Name:        op.name,
		Instance:    op.instance,
	}
}

func (c *Controller) addPending(op *pendingOperation) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	c.pending[op.id] = op
}

// pendingOp returns the operation, removing and closing it first if it has expired.
func (c *Controller) pendingOp(id string) (*pendingOperation, error) {
	c.pendingMu.Lock()
	op := c.pending[id]
	if op == nil {
		c.pendingMu.Unlock()
		return nil, errNoPendingOperation
	}
	if op.state == pendingStatePending && time.Now().After(op.expiresAt) {
		delete(c.pending, id)
		c.pendingMu.Unlock()
		op.close()
		return nil, errNoPendingOperation
	}
	c.pendingMu.Unlock()
	return op, nil
}

func (c *Controller) claimAttach(id, principal string, stream attachStream) (*pendingOperation, error) {
	op, err := c.pendingOp(id)
	if err != nil {
		return nil, err
	}
	if op.creator != principal {
		return nil, NewErrorResponse(http.StatusForbidden, fmt.Errorf("operation not created by this principal"))
	}
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if err := op.claim(stream); err != nil {
		return nil, err
	}
	return op, nil
}

func (c *Controller) beginStart(op *pendingOperation) error {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if op.state != pendingStatePending {
		return NewErrorResponse(http.StatusConflict, fmt.Errorf("operation already %s", op.state))
	}
	if len(op.claimed) != 3 {
		return NewErrorResponse(http.StatusConflict, fmt.Errorf("operation not ready: attach stdin, stdout and stderr first"))
	}
	op.state = pendingStateStarted
	return nil
}

func (c *Controller) removePending(op *pendingOperation) bool {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	if c.pending[op.id] == op {
		delete(c.pending, op.id)
		return true
	}
	return false
}

func (c *Controller) dropPending(op *pendingOperation) {
	if c.removePending(op) {
		op.close()
	}
}

func (c *Controller) attachFinished(op *pendingOperation, stream attachStream, copyErr error) {
	c.pendingMu.Lock()
	started := op.state != pendingStatePending
	c.pendingMu.Unlock()
	if started {
		// Stdin EOF while running is normal. Losing an output stream cancels
		// the operation, via the watch on op.ctx.
		if stream != attachStreamStdin {
			op.close()
		}
		return
	}
	c.dropPending(op)
}
