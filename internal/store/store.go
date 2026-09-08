package store

import (
	"context"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type Agent interface {
	Catalog() Catalog
	Runner(secretId string) Runner
}

type Catalog interface {
	Secrets() Secrets
	Instances() Instances
	Operations() Operations
}

type Secrets interface {
	List(ctx context.Context) (secrets.Secrets, error)
	Get(ctx context.Context, secretId string) (*secrets.Secret, error)
}

type Instances interface {
	List(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error)
	Get(ctx context.Context, instanceId string) (*secrets.Instance, error)
	GetActive(ctx context.Context, secretId string) (*secrets.Instance, error)
}

type Operations interface {
	List(ctx context.Context, secretId, instanceId *string, from, to int) ([]*secrets.Operation, error)
}

type Runner interface {
	Run(
		ctx context.Context,
		name secrets.OperationName,
		instanceId string,
		params executor.OperationParameters,
		proposer Proposer,
		stdio command.Stdio,
	) (startedInstance *secrets.Instance, wait Wait, err error)
}

type Wait func(ctx context.Context) (completedInstance *secrets.Instance, err error)

type Proposer interface {
	Propose(ctx context.Context, name secrets.OperationName, params executor.OperationParameters) error
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
