package executor

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type processCommandCall struct {
	Script string
	Stdin  string
	Env    command.Environment
}

func stdinString(r io.Reader) string {
	if r == nil {
		return ""
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestExecute(t *testing.T) {
	ctx := context.Background()
	var call processCommandCall
	saved := processCommand
	processCommand = func(cmd *command.Command, _ context.Context, stdio command.Stdio, env command.Environment) error {
		call = processCommandCall{Script: cmd.Script, Stdin: stdinString(stdio.Stdin), Env: env}
		return nil
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{
		Id:     "test-secret",
		Create: command.New("echo -n", nil, ""),
	}
	stdio := command.Stdio{Stdout: io.Discard, Stderr: io.Discard}
	err := Execute(ctx, s, secrets.Create, stdio, OperationParameters{}, "inst-1")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if call.Script != "echo -n" {
		t.Errorf("processCommand called with Script = %q, want %q", call.Script, "echo -n")
	}
	if call.Stdin != "" {
		t.Errorf("processCommand called with Stdin = %q, want %q", call.Stdin, "")
	}
	wantEnv := map[string]string{"INSTANCE": "inst-1", "SECRET": "test-secret", "FORCE": "false", "REASON": "", "STARTED_BY": ""}
	for k, v := range wantEnv {
		if call.Env[k] != v {
			t.Errorf("processCommand Env[%q] = %q, want %q", k, call.Env[k], v)
		}
	}
}

func TestExecute_withEnv(t *testing.T) {
	ctx := context.Background()
	var call processCommandCall
	saved := processCommand
	processCommand = func(cmd *command.Command, _ context.Context, stdio command.Stdio, env command.Environment) error {
		call = processCommandCall{Script: cmd.Script, Stdin: stdinString(stdio.Stdin), Env: env}
		return nil
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{
		Id:     "test-secret",
		Create: command.New("create-script", nil, ""),
	}
	params := OperationParameters{
		Reason:    "test",
		StartedBy: "tests",
	}
	stdio := command.Stdio{Stdin: strings.NewReader("stdin"), Stdout: io.Discard, Stderr: io.Discard}
	err := Execute(ctx, s, secrets.Create, stdio, params, "inst-1")
	if err != nil {
		t.Fatalf("Execute with env: %v", err)
	}
	if call.Script != "create-script" {
		t.Errorf("processCommand Script = %q, want create-script", call.Script)
	}
	if call.Stdin != "stdin" {
		t.Errorf("processCommand Stdin = %q, want stdin", call.Stdin)
	}
	if call.Env["SECRET"] != "test-secret" {
		t.Errorf("processCommand Env[SECRET] = %q, want test-secret", call.Env["SECRET"])
	}
	if call.Env["REASON"] != "test" || call.Env["STARTED_BY"] != "tests" {
		t.Errorf("processCommand Env REASON=%q STARTED_BY=%q, want test, tests", call.Env["REASON"], call.Env["STARTED_BY"])
	}
}

func TestExecute_noCommandForOp(t *testing.T) {
	ctx := context.Background()
	var called bool
	saved := processCommand
	processCommand = func(*command.Command, context.Context, command.Stdio, command.Environment) error {
		called = true
		return nil
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{Id: "no-cmds"}
	stdio := command.Stdio{Stdout: io.Discard, Stderr: io.Discard}
	err := Execute(ctx, s, secrets.Create, stdio, OperationParameters{}, "id")
	if err != nil {
		t.Fatalf("Execute when no command for op should succeed (no-op): %v", err)
	}
	if called {
		t.Error("processCommand should not be called when secret has no command for operation")
	}
}

func TestExecute_returnsCommandError(t *testing.T) {
	ctx := context.Background()
	wantErr := fmt.Errorf("command failed")
	saved := processCommand
	processCommand = func(*command.Command, context.Context, command.Stdio, command.Environment) error {
		return wantErr
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{Id: "x", Create: command.New("script", nil, "")}
	stdio := command.Stdio{Stdout: io.Discard, Stderr: io.Discard}
	err := Execute(ctx, s, secrets.Create, stdio, OperationParameters{}, "id")
	if err != wantErr {
		t.Errorf("Execute err = %v, want %v", err, wantErr)
	}
}

func TestExecute_noCommand(t *testing.T) {
	ctx := context.Background()
	s := &secrets.Secret{Id: "leaf"}
	stdio := command.Stdio{Stdin: strings.NewReader("input"), Stdout: io.Discard, Stderr: io.Discard}
	err := Execute(ctx, s, secrets.Create, stdio, OperationParameters{}, "id")
	if err != nil {
		t.Errorf("Execute with no command for op should succeed (no-op): %v", err)
	}
}

func TestOperationParameters_Validate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		p := OperationParameters{Reason: "any old reason"}
		if err := p.Validate(0); err != nil {
			t.Errorf("Validate(0): %v", err)
		}
		if err := p.Validate(14); err != nil {
			t.Errorf("Validate(14): %v", err)
		}
		err := p.Validate(13)
		if err == nil {
			t.Fatal("expected error for long reason")
		}
		if fmt.Sprint(err) != "reason too long (14 exceeds max of 13 bytes)" {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
