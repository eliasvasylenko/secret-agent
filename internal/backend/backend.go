package backend

import (
	"context"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type Backend interface {
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
	// Run persists the operation and starts background work before returning.
	// ctx covers this invocation only (accept / persist). Implementations must
	// not use it as the lifetime of execute or I/O pumps; Handle.Cancel stops that work.
	Run(
		ctx context.Context,
		name secrets.OperationName,
		instanceId string,
		params executor.OperationParameters,
		proposer Proposer,
		stdio command.Stdio,
	) (startedInstance *secrets.Instance, handle Handle, err error)
}

// Handle joins background work started before Run returned.
type Handle interface {
	// Wait blocks until completion. ctx abandons waiting only.
	Wait(ctx context.Context) (completedInstance *secrets.Instance, err error)
	// Cancel stops the in-flight op.
	Cancel(ctx context.Context) error
}

// Proposer approves by returning nil and rejects by returning an error.
// A delegated grant calls Propose and runs only after that nil return has recorded
// an eligible principal. A nil Proposer fails that operation.
type Proposer interface {
	Propose(ctx context.Context, name secrets.OperationName, params executor.OperationParameters) error
}

var ErrNotApprover = fmt.Errorf("principal is not eligible to approve this operation")

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
