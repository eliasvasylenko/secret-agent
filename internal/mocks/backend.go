package mocks

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type MockBackend struct {
	Mock
}

func (a *MockBackend) Catalog() backend.Catalog {
	return nextCall(&a.Mock, a.Catalog)()
}

func (a *MockBackend) Runner(secretId string) backend.Runner {
	return nextCall(&a.Mock, a.Runner)(secretId)
}

type MockCatalog struct {
	Mock
}

func (c *MockCatalog) Secrets() backend.Secrets {
	return nextCall(&c.Mock, c.Secrets)()
}

func (c *MockCatalog) Instances() backend.Instances {
	return nextCall(&c.Mock, c.Instances)()
}

func (c *MockCatalog) Operations() backend.Operations {
	return nextCall(&c.Mock, c.Operations)()
}

type MockSecrets struct {
	Mock
}

func (s *MockSecrets) List(ctx context.Context) (secrets.Secrets, error) {
	return nextCall(&s.Mock, s.List)(ctx)
}

func (s *MockSecrets) Get(ctx context.Context, secretId string) (*secrets.Secret, error) {
	return nextCall(&s.Mock, s.Get)(ctx, secretId)
}

type MockInstances struct {
	Mock
}

func (i *MockInstances) List(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error) {
	return nextCall(&i.Mock, i.List)(ctx, secretId, from, to)
}

func (i *MockInstances) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Get)(ctx, instanceId)
}

func (i *MockInstances) GetActive(ctx context.Context, secretId string) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.GetActive)(ctx, secretId)
}

type MockOperations struct {
	Mock
}

func (o *MockOperations) List(ctx context.Context, secretId, instanceId *string, from, to int) ([]*secrets.Operation, error) {
	return nextCall(&o.Mock, o.List)(ctx, secretId, instanceId, from, to)
}

type MockRunner struct {
	Mock
}

func (r *MockRunner) Run(
	ctx context.Context,
	name secrets.OperationName,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, backend.Handle, error) {
	return nextCall(&r.Mock, r.Run)(ctx, name, instanceId, params, proposer, stdio)
}
