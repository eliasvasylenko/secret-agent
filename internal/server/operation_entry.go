package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/uuid"
)

var errNoOperation = NewErrorResponse(http.StatusNotFound, fmt.Errorf("no such operation"))

const (
	defaultPendingOperationTTL  = 10 * time.Minute
	defaultFinishedOperationTTL = 2 * time.Minute
)

// operationLeases is how long an operation is kept while waiting to start,
// and how long its outcome is kept once it has finished.
type operationLeases struct {
	pending  time.Duration
	finished time.Duration
}

func newOperationLeases(pending, finished time.Duration) operationLeases {
	if pending <= 0 {
		pending = defaultPendingOperationTTL
	}
	if finished <= 0 {
		finished = defaultFinishedOperationTTL
	}
	return operationLeases{pending: pending, finished: finished}
}

// operationMap is the operations this process currently knows, by id.
// It adds an entry and removes that entry when it closes.
type operationMap struct {
	m sync.Map
}

func (t *operationMap) add(e *operationEntry) {
	// Findable before the lease starts, so the timer cannot fire first and
	// then lose the delete to the add.
	t.m.Store(e.id(), e)
	t.lease(e, e.leases.pending)
}

func (t *operationMap) remove(e *operationEntry) { t.m.Delete(e.id()) }

func (t *operationMap) get(id string) (*operationEntry, error) {
	entry, ok := t.m.Load(id)
	if !ok {
		return nil, errNoOperation
	}
	return entry.(*operationEntry), nil
}

// lease closes e after ttl if it is still in the state it has now.
func (t *operationMap) lease(e *operationEntry, ttl time.Duration) {
	from, ok := e.setLease(ttl)
	if !ok {
		return
	}
	time.AfterFunc(ttl, func() {
		if e.expire(from) {
			t.remove(e)
		}
	})
}

func (t *operationMap) cancel(e *operationEntry) error {
	err, closed := e.cancel()
	if closed {
		t.remove(e)
	}
	return err
}

func (t *operationMap) attachEnded(e *operationEntry, att *attachment) {
	if e.attachEnded(att) {
		t.remove(e)
	}
}

// finish records the outcome and keeps the entry for the finished lease.
func (t *operationMap) finish(e *operationEntry, instance *secrets.Instance, err error) {
	e.finish(instance, err)
	t.lease(e, e.leases.finished)
}

// watch waits for the run and records how it finished.
func (t *operationMap) watch(e *operationEntry, handle backend.Handle) {
	go func() {
		final, err := handle.Wait(e.ctx)
		if e.ctx.Err() != nil {
			_ = handle.Cancel(context.Background())
			final, err = handle.Wait(context.Background())
		}
		t.finish(e, final, err)
	}()
}

type operationState string

const (
	operationPending   operationState = "pending"
	operationStarted   operationState = "started"
	operationCompleted operationState = "completed"
	operationFailed    operationState = "failed"
	// closed is not a client state. The map drops the entry, and a stale
	// pointer cannot transition it again.
	operationClosed operationState = "closed"
)

// operationEntry is one operation this process is running: the operation
// record, the attaches, and the run.
//
// It stays pending until start, then started until it finishes completed or
// failed. Cancel, a dropped attach before start, or the lease expiring
// closes it. pending, completed, and failed expire. started does not.
//
// Lock mu around transitions. Don't call out while holding it.
type operationEntry struct {
	params    executor.OperationParameters
	leases    operationLeases
	ctx       context.Context
	cancelRun context.CancelFunc
	done      chan struct{}

	// byFd maps each descriptor to its attachment. ctty is the controlling
	// terminal descriptor, or command.NoTty.
	byFd map[int]*attachment
	ctty int

	mu sync.Mutex
	// op's identity fields are immutable; its lifecycle fields (StartedBy,
	// StartedAt, CompletedAt, FailedAt, and InstanceId for create) advance
	// under mu as the instance reports them.
	op        secrets.Operation
	state     operationState
	expiresAt time.Time
	instance  *secrets.Instance
}

// newOperationEntry creates a pending operation. The map adds it.
func newOperationEntry(creator, secretId, instanceId string, name secrets.OperationName, params executor.OperationParameters, leases operationLeases) *operationEntry {
	ctx, cancel := context.WithCancel(context.Background())
	return &operationEntry{
		params:    params,
		leases:    leases,
		ctx:       ctx,
		cancelRun: cancel,
		done:      make(chan struct{}),
		ctty:      command.NoTty,
		op: secrets.Operation{
			Id:         uuid.NewString(),
			SecretId:   secretId,
			InstanceId: instanceId,
			Name:       name,
			Forced:     params.Forced,
			Reason:     params.Reason,
			CreatedBy:  creator,
			CreatedAt:  time.Now(),
		},
		state: operationPending,
	}
}

func (e *operationEntry) id() string        { return e.op.Id }
func (e *operationEntry) createdBy() string { return e.op.CreatedBy }
func (e *operationEntry) secretId() string  { return e.op.SecretId }

// files is the file table built from the attaches so far.
func (e *operationEntry) files() command.Files {
	files := command.Files{Tty: command.NoTty}
	last := -1
	for fd := range e.byFd {
		if fd > last {
			last = fd
		}
	}
	if last >= 0 {
		files.Fds = make([]*os.File, last+1)
		for fd, att := range e.byFd {
			files.Fds[fd] = att.process
		}
	}
	files.Tty = e.ctty
	return files
}

// setLease records the expiry and the state it applies to. A closed entry
// is not leased.
func (e *operationEntry) setLease(ttl time.Duration) (operationState, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == operationClosed {
		return "", false
	}
	e.expiresAt = time.Now().Add(ttl)
	return e.state, true
}

// closeLocked stops the run and closes attaches. Caller holds mu.
func (e *operationEntry) closeLocked() {
	e.state = operationClosed
	e.cancelRun()
	e.closeAttachments()
	e.signalDoneLocked()
}

// signalDoneLocked wakes waiters. Caller holds mu. Safe to call twice.
func (e *operationEntry) signalDoneLocked() {
	select {
	case <-e.done:
	default:
		close(e.done)
	}
}

// wait blocks until the operation finishes, ctx is done, or d elapses.
func (e *operationEntry) wait(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-e.done:
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (e *operationEntry) closeAttachments() {
	seen := map[*attachment]struct{}{}
	for _, att := range e.byFd {
		if _, ok := seen[att]; ok {
			continue
		}
		seen[att] = struct{}{}
		att.close()
	}
}

func (e *operationEntry) conflict() error {
	return NewErrorResponse(http.StatusConflict, fmt.Errorf("operation already %s", e.state))
}

// claimAttach opens the file for these descriptors. Each descriptor once,
// and only one ctty. Pending only.
func (e *operationEntry) claimAttach(principal string, fds []int, mode command.FileMode) (*attachment, error) {
	if e.createdBy() != principal {
		return nil, NewErrorResponse(http.StatusForbidden, fmt.Errorf("operation not created by this principal"))
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.state {
	case operationClosed:
		return nil, errNoOperation
	case operationPending:
	default:
		return nil, e.conflict()
	}
	for _, fd := range fds {
		if e.byFd[fd] != nil {
			return nil, NewErrorResponse(http.StatusConflict, fmt.Errorf("fd %d already attached", fd))
		}
	}
	if mode == command.Ctty && e.ctty != command.NoTty {
		return nil, NewErrorResponse(http.StatusConflict, fmt.Errorf("controlling terminal already attached"))
	}
	att, err := newAttachment(fds, mode)
	if err != nil {
		return nil, NewErrorResponse(http.StatusInternalServerError, err)
	}
	if e.byFd == nil {
		e.byFd = make(map[int]*attachment)
	}
	for _, fd := range fds {
		e.byFd[fd] = att
	}
	if mode == command.Ctty {
		e.ctty = fds[0]
	}
	return att, nil
}

// start moves pending to started. Descriptors that were not attached stay
// unattached. The caller runs the operation after this returns.
func (e *operationEntry) start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.state {
	case operationClosed:
		return errNoOperation
	case operationPending:
	default:
		return e.conflict()
	}
	e.state = operationStarted
	e.expiresAt = time.Time{}
	return nil
}

// started records the instance the backend accepted.
func (e *operationEntry) started(instance *secrets.Instance) {
	if instance == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.instance = instance
	e.op.StartedBy = instance.Operation.StartedBy
	e.op.StartedAt = instance.Operation.StartedAt
	if e.op.InstanceId == "" {
		e.op.InstanceId = instance.Id
	}
}

// finish records completed or failed and closes the attaches.
func (e *operationEntry) finish(instance *secrets.Instance, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if instance != nil {
		e.instance = instance
		e.op.CompletedAt = instance.Operation.CompletedAt
		e.op.FailedAt = instance.Operation.FailedAt
	}
	if err != nil {
		e.state = operationFailed
		if instance == nil {
			log.Printf("operation %s failed without a final instance: %v", e.op.Id, err)
		}
	} else {
		e.state = operationCompleted
	}
	e.cancelRun()
	e.closeAttachments()
	e.signalDoneLocked()
}

// cancel closes a pending operation immediately. A started one is
// cancelled and stays until watch finishes it. A finished one is left
// to expire. closed is true when the map should drop the entry.
func (e *operationEntry) cancel() (err error, closed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.state {
	case operationClosed:
		return errNoOperation, false
	case operationStarted:
		e.cancelRun()
		return nil, false
	case operationPending:
		e.closeLocked()
		return nil, true
	default:
		return e.conflict(), false
	}
}

// attachEnded handles a copy finishing. Before start, that drops the
// operation. While running, EOF on a file the process only reads is fine.
// Losing one it writes cancels the run.
func (e *operationEntry) attachEnded(att *attachment) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch e.state {
	case operationPending:
		e.closeLocked()
		return true
	case operationStarted:
		if att.mode.Writes() {
			e.cancelRun()
		}
	}
	return false
}

// expire closes the entry if it is still in the state the lease was for.
// The bool is true when the map should drop the entry.
func (e *operationEntry) expire(from operationState) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state != from {
		return false
	}
	e.closeLocked()
	return true
}

func (e *operationEntry) operation() secrets.Operation {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.op
}

func (e *operationEntry) snapshot() (OperationStatusResponse, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == operationClosed {
		return OperationStatusResponse{}, errNoOperation
	}
	return OperationStatusResponse{
		Operation: e.op,
		State:     string(e.state),
		ExpiresAt: e.expiresAt,
		Instance:  e.instance,
	}, nil
}
