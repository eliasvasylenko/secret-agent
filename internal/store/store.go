package store

import (
	"context"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type Store interface {
	Secrets() Secrets
	Instances() Instances
	Operations() Operations
}

type Secrets interface {
	List(ctx context.Context) (secrets.Secrets, error)
	Get(ctx context.Context, secretId string) (*secrets.Secret, error)
}

type Instances interface {
	List(ctx context.Context, secretId *string, from int, to int) (secrets.Instances, error)
	Get(ctx context.Context, instanceId string) (*secrets.Instance, error)
	GetActive(ctx context.Context, secretId string) (*secrets.Instance, error)
}

type Operations interface {
	Start(ctx context.Context, op string, parameters executor.OperationParameters, proposer Proposer, stdio command.Stdio) (*secrets.Instance, error)
	List(ctx context.Context, secretId *string, instanceId *string, from int, to int) ([]*secrets.Operation, error)
}

type OperationResult struct {
	Instance *secrets.Instance
	ExitCode int
}

type Proposer interface {
	Propose(ctx context.Context, op string, parameters executor.OperationParameters) error
}

type StaleOperationError struct {
	Expected int
	Latest   int
}

func (e *StaleOperationError) Error() string {
	return fmt.Sprintf("stale operation: expected %d, latest is %d", e.Expected, e.Latest)
}

type UnknownOperationError struct {
	Expected int
	Latest   int
}

func (e *UnknownOperationError) Error() string {
	return fmt.Sprintf("unknown operation: expected %d, latest is %d", e.Expected, e.Latest)
}
