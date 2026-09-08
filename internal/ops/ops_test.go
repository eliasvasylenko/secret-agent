package ops_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/mocks"
	"github.com/eliasvasylenko/secret-agent/internal/ops"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
)

type noopProposer struct{}

func (noopProposer) Propose(context.Context, secrets.OperationName, executor.OperationParameters) error {
	return nil
}

type stubHandle struct {
	waitFn   func(context.Context) (*secrets.Instance, error)
	cancelFn func(context.Context) error
}

func (h stubHandle) Wait(ctx context.Context) (*secrets.Instance, error) {
	return h.waitFn(ctx)
}

func (h stubHandle) Cancel(ctx context.Context) error {
	return h.cancelFn(ctx)
}

func doneHandle(completed *secrets.Instance, err error) backend.Handle {
	return stubHandle{
		waitFn:   func(context.Context) (*secrets.Instance, error) { return completed, err },
		cancelFn: func(context.Context) error { return nil },
	}
}

func TestCreate_runAndWait(t *testing.T) {
	ctx := context.Background()
	started := &secrets.Instance{Id: "inst-1"}
	completed := &secrets.Instance{Id: "inst-1"}

	var mockRunner mocks.MockRunner
	defer mockRunner.Validate(t)

	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		context.Context,
		secrets.OperationName,
		string,
		executor.OperationParameters,
		backend.Proposer,
		command.Stdio,
	) (*secrets.Instance, backend.Handle, error) {
		return started, doneHandle(completed, nil), nil
	})

	got, err := ops.Create(ctx, &mockRunner, executor.OperationParameters{}, noopProposer{}, command.Stdio{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got != completed {
		t.Fatalf("Create instance = %p, want %p", got, completed)
	}
}

func TestCreate_runError(t *testing.T) {
	ctx := context.Background()
	runErr := errors.New("run failed")

	var mockRunner mocks.MockRunner
	defer mockRunner.Validate(t)

	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		context.Context,
		secrets.OperationName,
		string,
		executor.OperationParameters,
		backend.Proposer,
		command.Stdio,
	) (*secrets.Instance, backend.Handle, error) {
		return nil, nil, runErr
	})

	_, err := ops.Create(ctx, &mockRunner, executor.OperationParameters{}, noopProposer{}, command.Stdio{})
	if !errors.Is(err, runErr) {
		t.Fatalf("Create err = %v, want %v", err, runErr)
	}
}

func TestActivate_passesInstanceId(t *testing.T) {
	ctx := context.Background()
	const instanceId = "inst-42"

	var mockRunner mocks.MockRunner
	defer mockRunner.Validate(t)

	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		_ context.Context,
		name secrets.OperationName,
		gotInstanceId string,
		_ executor.OperationParameters,
		_ backend.Proposer,
		_ command.Stdio,
	) (*secrets.Instance, backend.Handle, error) {
		if name != secrets.Activate {
			t.Fatalf("Run name = %q, want activate", name)
		}
		if gotInstanceId != instanceId {
			t.Fatalf("Run instanceId = %q, want %q", gotInstanceId, instanceId)
		}
		return &secrets.Instance{Id: instanceId}, doneHandle(&secrets.Instance{Id: instanceId}, nil), nil
	})

	_, err := ops.Activate(ctx, &mockRunner, instanceId, executor.OperationParameters{}, noopProposer{}, command.Stdio{})
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
}

func TestRun_cancelOnWaitContextDone(t *testing.T) {
	ctx, stop := context.WithCancel(context.Background())
	stop()

	var canceled bool
	handle := stubHandle{
		waitFn: func(ctx context.Context) (*secrets.Instance, error) {
			return nil, ctx.Err()
		},
		cancelFn: func(context.Context) error {
			canceled = true
			return nil
		},
	}

	var mockRunner mocks.MockRunner
	defer mockRunner.Validate(t)

	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		context.Context,
		secrets.OperationName,
		string,
		executor.OperationParameters,
		backend.Proposer,
		command.Stdio,
	) (*secrets.Instance, backend.Handle, error) {
		return &secrets.Instance{Id: "inst-1"}, handle, nil
	})

	_, err := ops.Create(ctx, &mockRunner, executor.OperationParameters{}, noopProposer{}, command.Stdio{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Create err = %v, want context.Canceled", err)
	}
	if !canceled {
		t.Fatal("expected handle.Cancel after wait ctx was canceled")
	}
}
