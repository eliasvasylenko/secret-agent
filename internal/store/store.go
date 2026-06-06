package store

import (
	"context"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
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

	// Create a new instance of the secret, returning immediately when the operation is started
	Create(ctx context.Context, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Destroy an instance of the secret, returning immediately when the operation is started
	Destroy(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Activate an instance of the secret, returning immediately when the operation is started
	Activate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Deactivate an instance of the secret, returning immediately when the operation is started
	Deactivate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Test an instance of the secret, returning immediately when the operation is started
	Test(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Await the completion of an operation, blocking until the operation is completed or the context is cancelled
	Await(ctx context.Context, instanceId string, operationNumber int) (*secrets.Instance, error)

	// Cancel an operation, returning immediately when the operation is cancelled
	Cancel(ctx context.Context, instanceId string, operationNumber int) error

	// Read the operation history of an instance, from the given inclusive index, to the given exclusive index
	History(ctx context.Context, instanceId string, from int, to int) ([]*secrets.Operation, error)
}

// StaleOperationError is returned when the requested operation number has been
// superseded by a newer operation on the same instance.
type StaleOperationError struct {
	Expected int
	Latest   int
}

func (e *StaleOperationError) Error() string {
	return fmt.Sprintf("stale operation: expected %d, latest is %d", e.Expected, e.Latest)
}

// UnknownOperationError is returned when the requested operation number has
// not been recorded yet.
type UnknownOperationError struct {
	Expected int
	Latest   int
}

func (e *UnknownOperationError) Error() string {
	return fmt.Sprintf("unknown operation: expected %d, latest is %d", e.Expected, e.Latest)
}
