package mocks

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

type MockSecrets struct {
	Mock
}

func (s *MockSecrets) List(ctx context.Context) (secrets.Secrets, error) {
	return nextCall(&s.Mock, s.List)(ctx)
}
func (s *MockSecrets) Get(ctx context.Context, secretId string) (*secrets.Secret, error) {
	return nextCall(&s.Mock, s.Get)(ctx, secretId)
}
func (s *MockSecrets) History(ctx context.Context, secretId string, from int, to int) ([]*secrets.Operation, error) {
	return nextCall(&s.Mock, s.History)(ctx, secretId, from, to)
}
func (s *MockSecrets) Instances(secretId string) store.Instances {
	return nextCall(&s.Mock, s.Instances)(secretId)
}

type MockInstances struct {
	Mock
}

func (i *MockInstances) List(ctx context.Context, from int, to int) (secrets.Instances, error) {
	return nextCall(&i.Mock, i.List)(ctx, from, to)
}
func (i *MockInstances) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Get)(ctx, instanceId)
}
func (i *MockInstances) GetActive(ctx context.Context) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.GetActive)(ctx)
}
func (i *MockInstances) Create(ctx context.Context, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Create)(ctx, parameters, stdio)
}
func (i *MockInstances) Destroy(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Destroy)(ctx, instanceId, parameters, stdio)
}
func (i *MockInstances) Activate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Activate)(ctx, instanceId, parameters, stdio)
}
func (i *MockInstances) Deactivate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Deactivate)(ctx, instanceId, parameters, stdio)
}
func (i *MockInstances) Test(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Test)(ctx, instanceId, parameters, stdio)
}
func (i *MockInstances) Operations(instanceId string) store.Operations {
	return nextCall(&i.Mock, i.Operations)(instanceId)
}

type MockOperations struct {
	Mock
}

func (o *MockOperations) List(ctx context.Context, from int, to int) ([]*secrets.Operation, error) {
	return nextCall(&o.Mock, o.List)(ctx, from, to)
}
func (o *MockOperations) Process(ctx context.Context, operationNumber int) (*store.Process, error) {
	return nextCall(&o.Mock, o.Process)(ctx, operationNumber)
}
func (o *MockOperations) Await(ctx context.Context, operationNumber int) (store.Event, *secrets.Instance, error) {
	return nextCall(&o.Mock, o.Await)(ctx, operationNumber)
}
func (o *MockOperations) Cancel(ctx context.Context, operationNumber int) error {
	return nextCall(&o.Mock, o.Cancel)(ctx, operationNumber)
}
