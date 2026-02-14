package mocks

import (
	"context"

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
func (i *MockInstances) Create(ctx context.Context, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Create)(ctx, parameters)
}
func (i *MockInstances) Destroy(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Destroy)(ctx, instanceId, parameters)
}
func (i *MockInstances) Activate(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Activate)(ctx, instanceId, parameters)
}
func (i *MockInstances) Deactivate(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Deactivate)(ctx, instanceId, parameters)
}
func (i *MockInstances) Test(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	return nextCall(&i.Mock, i.Test)(ctx, instanceId, parameters)
}
func (i *MockInstances) History(ctx context.Context, instanceId string, from int, to int) ([]*secrets.Operation, error) {
	return nextCall(&i.Mock, i.History)(ctx, instanceId, from, to)
}
