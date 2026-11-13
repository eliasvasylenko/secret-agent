package backend

import (
	"context"
	"io"

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
}

type Secrets interface {
	List(ctx context.Context) (secrets.Secrets, error)
	// Get returns *SecretNotFoundError when the plan is missing. A
	// successful call returns a non-nil secret.
	Get(ctx context.Context, secretId string) (*secrets.Secret, error)
}

type Instances interface {
	List(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error)
	// Get returns *InstanceNotFoundError when the instance is missing. A
	// successful call returns a non-nil instance.
	Get(ctx context.Context, instanceId string) (*secrets.Instance, error)
	// GetActive returns (nil, nil) when the secret has no active instance.
	GetActive(ctx context.Context, secretId string) (*secrets.Instance, error)
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
		stdio command.Files,
	) (startedInstance *secrets.Instance, handle Handle, err error)
}

// Handle joins background work started before Run returned.
type Handle interface {
	// Wait blocks until completion. ctx abandons waiting only.
	Wait(ctx context.Context) (completedInstance *secrets.Instance, err error)
	// Cancel stops the in-flight op.
	Cancel(ctx context.Context) error
}

type Proposer interface {
	// Propose puts the operator on pipe, a raw connection to the host that asked
	// for approval. The operator authenticates to that host on those bytes.
	// Nil means the host recorded the approval. pipe is nil only for an in-process call.
	Propose(ctx context.Context, secretID string, name secrets.OperationName, params executor.OperationParameters, pipe io.ReadWriteCloser) error
}
