package sqlite

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

// Backend is the in-process backend.Backend implementation backed by sqlite.
type Backend struct {
	repo *Repository
}

// Open opens a sqlite database and returns a Backend.
func Open(ctx context.Context, dbFile string, secrets secrets.Secrets, debug bool, maxReasonLen int) (*Backend, error) {
	repo, err := NewRepository(ctx, dbFile, secrets, debug, maxReasonLen)
	if err != nil {
		return nil, err
	}
	return &Backend{repo: repo}, nil
}

func (b *Backend) Close() {
	b.repo.Close()
}

func (b *Backend) Catalog() backend.Catalog {
	return catalog{repo: b.repo}
}

func (b *Backend) Runner(secretId string) backend.Runner {
	return &runner{state: b.repo.secretState(secretId)}
}

type catalog struct {
	repo *Repository
}

func (c catalog) Secrets() backend.Secrets {
	return secretsCatalog{repo: c.repo}
}

func (c catalog) Instances() backend.Instances {
	return instancesCatalog{repo: c.repo}
}

func (c catalog) Operations() backend.Operations {
	return operationsCatalog{repo: c.repo}
}

type secretsCatalog struct {
	repo *Repository
}

func (s secretsCatalog) List(ctx context.Context) (secrets.Secrets, error) {
	return s.repo.listSecrets(ctx)
}

func (s secretsCatalog) Get(ctx context.Context, secretId string) (*secrets.Secret, error) {
	return s.repo.getSecret(ctx, secretId)
}

type instancesCatalog struct {
	repo *Repository
}

func (i instancesCatalog) List(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error) {
	return i.repo.listInstances(ctx, secretId, from, to)
}

func (i instancesCatalog) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	return i.repo.getInstance(ctx, instanceId)
}

func (i instancesCatalog) GetActive(ctx context.Context, secretId string) (*secrets.Instance, error) {
	return i.repo.getActiveInstance(ctx, secretId)
}

type operationsCatalog struct {
	repo *Repository
}

func (o operationsCatalog) List(ctx context.Context, secretId, instanceId *string, from, to int) ([]*secrets.Operation, error) {
	return o.repo.listOperations(ctx, secretId, instanceId, from, to)
}

type runner struct {
	state *secretState
}

func (r *runner) Run(
	ctx context.Context,
	name secrets.OperationName,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, backend.Handle, error) {
	_ = proposer

	var (
		instance  *secrets.Instance
		operation secrets.Operation
		err       error
	)
	switch name {
	case secrets.Create:
		instance, operation, err = r.state.beginCreate(ctx, params)
	default:
		instance, operation, err = r.state.beginUpdate(ctx, instanceId, name, params)
	}
	if err != nil {
		return nil, nil, err
	}
	return instance, r.state.launch(instance, operation, params, stdio), nil
}

func (h *opHandle) Wait(ctx context.Context) (*secrets.Instance, error) {
	select {
	case <-h.done:
		return h.final, h.waitErr
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *opHandle) Cancel(ctx context.Context) error {
	h.execCancel()
	select {
	case <-h.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

var _ backend.Backend = (*Backend)(nil)
var _ backend.Catalog = (catalog{})
var _ backend.Secrets = (secretsCatalog{})
var _ backend.Instances = (instancesCatalog{})
var _ backend.Operations = (operationsCatalog{})
var _ backend.Runner = (*runner)(nil)
var _ backend.Handle = (*opHandle)(nil)
