package server

import (
	"context"
	"errors"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type approvalAttempt struct {
	by     string
	result chan error
}

type parkedApproval struct {
	attempts chan approvalAttempt
	closed   chan struct{}
}

// runProposer is the Proposer the executing server passes into Runner.Run.
// Propose returns nil only after the eligible connection principal is recorded
// against the frozen grant. An ineligible principal leaves the call parked.
type runProposer struct {
	ctrl  *Controller
	store backend.Backend
	id    chan string
}

func newRunProposer(ctrl *Controller, store backend.Backend) *runProposer {
	return &runProposer{ctrl: ctrl, store: store, id: make(chan string, 1)}
}

func (p *runProposer) bind(instanceID string) {
	p.id <- instanceID
}

func (p *runProposer) Propose(ctx context.Context, _ secrets.OperationName, _ executor.OperationParameters) error {
	recorder, ok := p.store.(approvalRecorder)
	if !ok {
		return fmt.Errorf("store cannot record approval")
	}
	var instanceID string
	select {
	case instanceID = <-p.id:
	case <-ctx.Done():
		return ctx.Err()
	}
	parked := &parkedApproval{
		attempts: make(chan approvalAttempt),
		closed:   make(chan struct{}),
	}
	if err := p.ctrl.parkApproval(instanceID, parked); err != nil {
		return err
	}
	defer p.ctrl.unparkApproval(instanceID)
	defer close(parked.closed)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case attempt := <-parked.attempts:
			err := recorder.RecordApproval(ctx, instanceID, attempt.by)
			attempt.result <- err
			if err == nil {
				return nil
			}
			if !errors.Is(err, backend.ErrNotApprover) {
				return err
			}
		}
	}
}

type approvalRecorder interface {
	RecordApproval(ctx context.Context, instanceID, by string) error
}

func (c *Controller) parkApproval(instanceID string, parked *parkedApproval) error {
	c.approvalsMu.Lock()
	defer c.approvalsMu.Unlock()
	if _, ok := c.approvals[instanceID]; ok {
		return fmt.Errorf("approval already parked for %s", instanceID)
	}
	c.approvals[instanceID] = parked
	return nil
}

func (c *Controller) unparkApproval(instanceID string) {
	c.approvalsMu.Lock()
	delete(c.approvals, instanceID)
	c.approvalsMu.Unlock()
}

func (c *Controller) submitApproval(instanceID, by string) error {
	c.approvalsMu.Lock()
	parked := c.approvals[instanceID]
	c.approvalsMu.Unlock()
	if parked == nil {
		return errNoParkedApproval
	}
	result := make(chan error, 1)
	select {
	case <-parked.closed:
		return errNoParkedApproval
	case parked.attempts <- approvalAttempt{by: by, result: result}:
		return <-result
	}
}

var errNoParkedApproval = fmt.Errorf("operation is not awaiting approval")
