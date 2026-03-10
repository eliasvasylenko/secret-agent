package executor

import (
	"context"
	"fmt"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

// processCommandCall records a single call to the processCommand mock.
type processCommandCall struct {
	Script string
	Input  string
	Env    command.Environment
}

func TestExecute(t *testing.T) {
	ctx := context.Background()
	var call processCommandCall
	saved := processCommand
	processCommand = func(cmd *command.Command, _ context.Context, input string, env command.Environment) (string, error) {
		call = processCommandCall{Script: cmd.Script, Input: input, Env: env}
		return "mock-output", nil
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{
		Name:   "test-secret",
		Create: command.New("echo -n", nil, ""),
	}
	err := Execute(ctx, s, secrets.Create, "", OperationParameters{}, "inst-1")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if call.Script != "echo -n" {
		t.Errorf("processCommand called with Script = %q, want %q", call.Script, "echo -n")
	}
	if call.Input != "" {
		t.Errorf("processCommand called with Input = %q, want %q", call.Input, "")
	}
	wantEnv := map[string]string{"ID": "inst-1", "NAME": "test-secret", "FORCE": "false", "REASON": "", "STARTED_BY": ""}
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
	processCommand = func(cmd *command.Command, _ context.Context, input string, env command.Environment) (string, error) {
		call = processCommandCall{Script: cmd.Script, Input: input, Env: env}
		return "", nil
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{
		Name:   "test-secret",
		Create: command.New("create-script", nil, ""),
	}
	params := OperationParameters{
		Reason:    "test",
		StartedBy: "tests",
	}
	err := Execute(ctx, s, secrets.Create, "stdin", params, "inst-1")
	if err != nil {
		t.Fatalf("Execute with env: %v", err)
	}
	if call.Script != "create-script" {
		t.Errorf("processCommand Script = %q, want create-script", call.Script)
	}
	if call.Input != "stdin" {
		t.Errorf("processCommand Input = %q, want stdin", call.Input)
	}
	if call.Env["NAME"] != "test-secret" {
		t.Errorf("processCommand Env[NAME] = %q, want test-secret", call.Env["NAME"])
	}
	if call.Env["REASON"] != "test" || call.Env["STARTED_BY"] != "tests" {
		t.Errorf("processCommand Env REASON=%q STARTED_BY=%q, want test, tests", call.Env["REASON"], call.Env["STARTED_BY"])
	}
}

func TestExecute_noCommandForOp(t *testing.T) {
	ctx := context.Background()
	var called bool
	saved := processCommand
	processCommand = func(*command.Command, context.Context, string, command.Environment) (string, error) {
		called = true
		return "", nil
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{Name: "no-cmds"} // no command for Create
	err := Execute(ctx, s, secrets.Create, "", OperationParameters{}, "id")
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
	processCommand = func(*command.Command, context.Context, string, command.Environment) (string, error) {
		return "", wantErr
	}
	defer func() { processCommand = saved }()

	s := &secrets.Secret{Name: "x", Create: command.New("script", nil, "")}
	err := Execute(ctx, s, secrets.Create, "", OperationParameters{}, "id")
	if err != wantErr {
		t.Errorf("Execute err = %v, want %v", err, wantErr)
	}
}

func TestExecute_noCommand(t *testing.T) {
	ctx := context.Background()
	s := &secrets.Secret{Name: "leaf"} // no Create command
	err := Execute(ctx, s, secrets.Create, "input", OperationParameters{}, "id")
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
