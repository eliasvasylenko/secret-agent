package ops

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

func Create(
	ctx context.Context,
	runner backend.Runner,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, error) {
	return run(ctx, runner, secrets.Create, "", params, proposer, stdio)
}

func Destroy(
	ctx context.Context,
	runner backend.Runner,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, error) {
	return run(ctx, runner, secrets.Destroy, instanceId, params, proposer, stdio)
}

func Activate(
	ctx context.Context,
	runner backend.Runner,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, error) {
	return run(ctx, runner, secrets.Activate, instanceId, params, proposer, stdio)
}

func Deactivate(
	ctx context.Context,
	runner backend.Runner,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, error) {
	return run(ctx, runner, secrets.Deactivate, instanceId, params, proposer, stdio)
}

func Test(
	ctx context.Context,
	runner backend.Runner,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, error) {
	return run(ctx, runner, secrets.Test, instanceId, params, proposer, stdio)
}

func run(
	ctx context.Context,
	runner backend.Runner,
	name secrets.OperationName,
	instanceId string,
	params executor.OperationParameters,
	proposer backend.Proposer,
	stdio command.Stdio,
) (*secrets.Instance, error) {
	_, handle, err := runner.Run(ctx, name, instanceId, params, proposer, stdio)
	if err != nil {
		return nil, err
	}
	inst, err := handle.Wait(ctx)
	if ctx.Err() != nil {
		_ = handle.Cancel(context.Background())
	}
	return inst, err
}
