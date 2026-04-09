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

	// Start creating a new instance. Returns immediately after the operation is recorded;
	// the command runs asynchronously with output delivered via stdio.
	Create(ctx context.Context, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Start destroying an instance. Returns immediately; command runs asynchronously.
	Destroy(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Start activating an instance. Returns immediately; command runs asynchronously.
	Activate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Start deactivating an instance. Returns immediately; command runs asynchronously.
	Deactivate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Start testing an instance. Returns immediately; command runs asynchronously.
	Test(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error)

	// Block until the operation identified by operationNumber completes (success or failure).
	// If operationNumber is stale (a newer operation exists), returns the latest instance and a *StaleOperationError.
	Await(ctx context.Context, instanceId string, operationNumber int) (*secrets.Instance, error)

	// Read the operation history of a secret instance, from the given inclusive index, to the given exclusive index
	History(ctx context.Context, instanceId string, from int, to int) ([]*secrets.Operation, error)
}

// StaleOperationError is returned by Await when the requested operation number
// has been superseded by a newer operation on the same instance.
type StaleOperationError struct {
	Expected int
	Latest   int
}

func (e *UnknkownOperationError) Error() string {
	return fmt.Sprintf("unknown operation: expected %d, latest is %d", e.Expected, e.Latest)
}

// UnknkownOperationError is returned by Await when the requested operation number
// has not been recorded yet.
type UnknkownOperationError struct {
	Expected int
	Latest   int
}

func (e *StaleOperationError) Error() string {
	return fmt.Sprintf("stale operation: expected %d, latest is %d", e.Expected, e.Latest)
}
