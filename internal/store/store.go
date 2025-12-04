package store

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type Secrets interface {
	// List all secrets
	List(ctx context.Context) (secrets.Secrets, error)

	// Get the secret with the given id
	Get(ctx context.Context, secretId string) (*secrets.Secret, error)

	// Read the operation history of a secret, from the given inclusive index, to the given exclusive index
	History(ctx context.Context, secretId string, from int, to int) ([]*secrets.Operation, error)

	// The interfaces of the secret with the given id
	Instances(secretId string) Instances
}

type Instances interface {
	// List all instances
	List(ctx context.Context, from int, to int) (secrets.Instances, error)

	// Get the instance with the given ID
	Get(ctx context.Context, instanceId string) (*secrets.Instance, error)

	// Read the active instance of the secret
	GetActive(ctx context.Context) (*secrets.Instance, error)

	// Start creating a new instance with the given plan and ID, returning a function to complete the operation
	Create(ctx context.Context, parameters secrets.OperationParameters) (*secrets.Instance, error)

	// Start destroying the instance with the given ID, returning a function to complete the operation
	Destroy(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error)

	// Activate the instance with the given ID and secret name
	Activate(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error)

	// Deactivate the instance with the given ID and secret name
	Deactivate(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error)

	// Deactivate the instance with the given ID and secret name
	Test(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error)

	// Read the operation history of a secret instance, from the given inclusive index, to the given exclusive index
	History(ctx context.Context, instanceId string, from int, to int) ([]*secrets.Operation, error)
}
