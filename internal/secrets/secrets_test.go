package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		secrets, err := New([]*Secret{
			{Name: "a", Create: command.New("echo a", nil, "")},
			{Name: "b", Create: command.New("echo b", nil, "")},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(secrets) != 2 || secrets["a"] == nil || secrets["b"] == nil {
			t.Errorf("expected two secrets, got %v", secrets)
		}
	})
	t.Run("empty name", func(t *testing.T) {
		_, err := New([]*Secret{{Name: ""}})
		if err == nil {
			t.Fatal("expected error for empty name")
		}
		if fmt.Sprint(err) != "Secret name must not be empty" {
			t.Errorf("expected empty name error, got %v", err)
		}
	})
	t.Run("duplicate name", func(t *testing.T) {
		_, err := New([]*Secret{
			{Name: "x"},
			{Name: "x"},
		})
		if err == nil {
			t.Fatal("expected error for duplicate name")
		}
		if fmt.Sprint(err) != "Secret name 'x' must be unique" {
			t.Errorf("expected duplicate name error, got %v", err)
		}
	})
}

func TestSecrets_MarshalJSON(t *testing.T) {
	secrets := Secrets{
		"friend": {Name: "friend", Create: command.New("echo hello", nil, "")},
	}
	data, err := json.Marshal(secrets)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var decoded Secrets
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal after Marshal: %v", err)
	}
	if !cmp.Equal(secrets, decoded, cmpopts.IgnoreUnexported(Secret{}, command.Command{})) {
		t.Errorf("round-trip mismatch: %s", cmp.Diff(secrets, decoded, cmpopts.IgnoreUnexported(Secret{}, command.Command{})))
	}
}

// processCommandCall records a single call to the processCommand mock.
type processCommandCall struct {
	Script string
	Input  string
	Env    command.Environment
}

func TestSecret_Process(t *testing.T) {
	ctx := context.Background()
	var call processCommandCall
	saved := processCommand
	processCommand = func(cmd *command.Command, _ context.Context, input string, env command.Environment) (string, error) {
		call = processCommandCall{Script: cmd.Script, Input: input, Env: env}
		return "mock-output", nil
	}
	defer func() { processCommand = saved }()

	s := &Secret{
		Name:   "test-secret",
		Create: command.New("echo -n", nil, ""),
	}
	err := s.Process(ctx, Create, "", OperationParameters{}, "inst-1")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if call.Script != "echo -n" {
		t.Errorf("processCommand called with Script = %q, want %q", call.Script, "echo -n")
	}
	if call.Input != "" {
		t.Errorf("processCommand called with Input = %q, want %q", call.Input, "")
	}
	wantEnv := map[string]string{"ID": "inst-1", "NAME": "test-secret", "QID": "test-secret/inst-1", "QNAME": "test-secret", "FORCE": "false", "REASON": "", "STARTED_BY": ""}
	for k, v := range wantEnv {
		if call.Env[k] != v {
			t.Errorf("processCommand Env[%q] = %q, want %q", k, call.Env[k], v)
		}
	}
}

func TestSecret_Process_withEnv(t *testing.T) {
	ctx := context.Background()
	var call processCommandCall
	saved := processCommand
	processCommand = func(cmd *command.Command, _ context.Context, input string, env command.Environment) (string, error) {
		call = processCommandCall{Script: cmd.Script, Input: input, Env: env}
		return "", nil
	}
	defer func() { processCommand = saved }()

	s := &Secret{
		Name:   "test-secret",
		Create: command.New("create-script", nil, ""),
	}
	params := OperationParameters{
		Env:       command.Environment{"QNAME": "parent"},
		Reason:    "test",
		StartedBy: "tests",
	}
	err := s.Process(ctx, Create, "stdin", params, "inst-1")
	if err != nil {
		t.Fatalf("Process with env: %v", err)
	}
	if call.Script != "create-script" {
		t.Errorf("processCommand Script = %q, want create-script", call.Script)
	}
	if call.Input != "stdin" {
		t.Errorf("processCommand Input = %q, want stdin", call.Input)
	}
	if call.Env["QNAME"] != "parent/test-secret" {
		t.Errorf("processCommand Env[QNAME] = %q, want parent/test-secret", call.Env["QNAME"])
	}
	if call.Env["REASON"] != "test" || call.Env["STARTED_BY"] != "tests" {
		t.Errorf("processCommand Env REASON=%q STARTED_BY=%q, want test, tests", call.Env["REASON"], call.Env["STARTED_BY"])
	}
}

func TestSecret_Process_noCommandForOp(t *testing.T) {
	ctx := context.Background()
	var called bool
	saved := processCommand
	processCommand = func(*command.Command, context.Context, string, command.Environment) (string, error) {
		called = true
		return "", nil
	}
	defer func() { processCommand = saved }()

	s := &Secret{Name: "no-cmds"} // no Create/Destroy/etc
	err := s.Process(ctx, Create, "", OperationParameters{}, "id")
	if err != nil {
		t.Fatalf("Process when no command for op should succeed (no-op): %v", err)
	}
	if called {
		t.Error("processCommand should not be called when secret has no command for operation")
	}
}

func TestSecret_Process_returnsCommandError(t *testing.T) {
	ctx := context.Background()
	wantErr := fmt.Errorf("command failed")
	saved := processCommand
	processCommand = func(*command.Command, context.Context, string, command.Environment) (string, error) {
		return "", wantErr
	}
	defer func() { processCommand = saved }()

	s := &Secret{Name: "x", Create: command.New("script", nil, "")}
	err := s.Process(ctx, Create, "", OperationParameters{}, "id")
	if err != wantErr {
		t.Errorf("Process err = %v, want %v", err, wantErr)
	}
}

func TestSecret_processSubsteps_noDerive(t *testing.T) {
	ctx := context.Background()
	s := &Secret{Name: "leaf", Derive: nil}
	err := s.processSubsteps(ctx, Create, "input", OperationParameters{}, "id")
	if err != nil {
		t.Errorf("processSubsteps with nil Derive: %v", err)
	}
}

func TestSecret_Process_withDerivedSecrets(t *testing.T) {
	ctx := context.Background()
	var calls []processCommandCall
	saved := processCommand
	processCommand = func(cmd *command.Command, _ context.Context, input string, env command.Environment) (string, error) {
		calls = append(calls, processCommandCall{Script: cmd.Script, Input: input, Env: env})
		return fmt.Sprintf("%s-output", cmd.Script), nil
	}
	defer func() { processCommand = saved }()

	parent := &Secret{
		Name:   "parent",
		Create: command.New("parent-create", nil, ""),
		Derive: Secrets{
			"child": {
				Name:   "child",
				Create: command.New("child-create", nil, ""),
			},
		},
	}
	err := parent.Process(ctx, Create, "initial-input", OperationParameters{}, "inst-1")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("processCommand called %d times, want 2", len(calls))
	}
	// Parent runs first with the initial input
	if calls[0].Script != "parent-create" || calls[0].Input != "initial-input" {
		t.Errorf("first call: Script=%q Input=%q, want parent-create-output, initial-input", calls[0].Script, calls[0].Input)
	}
	if calls[0].Env["NAME"] != "parent" || calls[0].Env["QNAME"] != "parent" {
		t.Errorf("first call env: NAME=%q QNAME=%q, want parent, parent", calls[0].Env["NAME"], calls[0].Env["QNAME"])
	}
	// Derived secret runs with parent's output as input
	if calls[1].Script != "child-create" || calls[1].Input != "parent-create-output" {
		t.Errorf("second call: Script=%q Input=%q, want child-create, parent-create-output", calls[1].Script, calls[1].Input)
	}
	if calls[1].Env["NAME"] != "child" || calls[1].Env["QNAME"] != "parent/child" {
		t.Errorf("second call env: NAME=%q QNAME=%q, want child, parent/child", calls[1].Env["NAME"], calls[1].Env["QNAME"])
	}
}

func TestSecret_Process_derivedSecretError(t *testing.T) {
	ctx := context.Background()
	wantErr := fmt.Errorf("derived command failed")
	saved := processCommand
	processCommand = func(cmd *command.Command, _ context.Context, input string, env command.Environment) (string, error) {
		if cmd.Script == "child-create" {
			return "", wantErr
		}
		return "parent-output", nil
	}
	defer func() { processCommand = saved }()

	parent := &Secret{
		Name:   "parent",
		Create: command.New("parent-create", nil, ""),
		Derive: Secrets{
			"child": {Name: "child", Create: command.New("child-create", nil, "")},
		},
	}
	err := parent.Process(ctx, Create, "", OperationParameters{}, "id")
	if err != wantErr {
		t.Errorf("Process err = %v, want %v", err, wantErr)
	}
}

func TestLoadPlans(t *testing.T) {
	friend := &Secret{
		Name:   "friend",
		Create: command.New("echo hello friend", nil, ""),
	}
	dbCreds := &Secret{
		Name:   "db-creds",
		Create: command.New("openssl rand -base64 32", nil, ""),
		Derive: Secrets{
			"service": &Secret{
				Name:       "service",
				Create:     command.New("cat > /etc/enrypted-creds/$NAME/$ID.cred", nil, ""),
				Destroy:    command.New("rm -f /etc/enrypted-creds/$NAME/$ID.cred", nil, ""),
				Activate:   command.New("cp -f /etc/enrypted-creds/$NAME/$ID.cred /etc/enrypted-creds/service.cred", nil, ""),
				Deactivate: command.New("rm -f /etc/enrypted-creds/service.cred", nil, ""),
			},
			"remote": &Secret{
				Name:       "remote",
				Create:     command.New("ssh host -csecret-agent create $NAME $ID", nil, ""),
				Destroy:    command.New("ssh host -csecret-agent destroy $NAME $ID", nil, ""),
				Activate:   command.New("ssh host -csecret-agent activate $NAME $ID", nil, ""),
				Deactivate: command.New("ssh host -csecret-agent deactivate $NAME $ID", nil, ""),
				Test:       command.New("ssh host -csecret-agent test $NAME $ID", nil, ""),
			},
		},
	}
	tests := []struct {
		file            string
		expectedErr     error
		expectedSecrets Secrets
	}{
		{
			file: "simple",
			expectedSecrets: Secrets{
				"friend": friend,
			},
		},
		{
			file: "complex",
			expectedSecrets: Secrets{
				"db-creds": dbCreds,
			},
		},
		{
			file:        "multiple",
			expectedErr: nil,
			expectedSecrets: Secrets{
				"friend":   friend,
				"db-creds": dbCreds,
			},
		},
	}
	for _, tc := range tests {
		t.Run("Test load "+tc.file+" plans", func(t *testing.T) {
			secretsBytes, err := os.ReadFile(fmt.Sprintf("./test/secrets/%v.json", tc.file))
			if err != nil {
				t.Error(err)
				return
			}
			var secrets Secrets
			err = json.Unmarshal(secretsBytes, &secrets)
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}
			if !cmp.Equal(tc.expectedSecrets, secrets, cmpopts.IgnoreUnexported(Secret{}, command.Command{})) {
				diff := cmp.Diff(tc.expectedSecrets, secrets, cmpopts.IgnoreUnexported(Secret{}, command.Command{}))
				t.Errorf("Plans did not match: %v", diff)
			}
		})
	}
}

func TestNewInstances(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		instances, err := NewInstances([]*Instance{
			{Id: "id1", Secret: Secret{Name: "s1"}, Status: Status{OperationNumber: 1}},
			{Id: "id2", Secret: Secret{Name: "s2"}, Status: Status{OperationNumber: 2}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(instances) != 2 || instances["id1"] == nil || instances["id2"] == nil {
			t.Errorf("expected two instances, got %v", instances)
		}
	})
	t.Run("empty id", func(t *testing.T) {
		_, err := NewInstances([]*Instance{{Id: ""}})
		if err == nil {
			t.Fatal("expected error for empty id")
		}
		if fmt.Sprint(err) != "Instance ID must not be empty" {
			t.Errorf("expected empty id error, got %v", err)
		}
	})
	t.Run("duplicate id", func(t *testing.T) {
		_, err := NewInstances([]*Instance{
			{Id: "x"},
			{Id: "x"},
		})
		if err == nil {
			t.Fatal("expected error for duplicate id")
		}
		if fmt.Sprint(err) != "Instance ID 'x' must be unique" {
			t.Errorf("expected duplicate id error, got %v", err)
		}
	})
}

func TestInstances_UnmarshalJSON(t *testing.T) {
	data := `[{"id":"i1","secret":{"name":"s1"},"status":{"operationNumber":1,"name":"create"}}]`
	var instances Instances
	err := json.Unmarshal([]byte(data), &instances)
	if err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}
	if len(instances) != 1 || instances["i1"] == nil {
		t.Errorf("expected one instance, got %v", instances)
	}
	if instances["i1"].Secret.Name != "s1" {
		t.Errorf("instance secret name = %q", instances["i1"].Secret.Name)
	}
}

func TestInstances_MarshalJSON(t *testing.T) {
	instances := Instances{
		"id1": {Id: "id1", Secret: Secret{Name: "s1"}, Status: Status{OperationNumber: 2}},
		"id2": {Id: "id2", Secret: Secret{Name: "s2"}, Status: Status{OperationNumber: 1}},
	}
	data, err := json.Marshal(instances)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var decoded Instances
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal after Marshal: %v", err)
	}
	if len(decoded) != 2 {
		t.Errorf("expected 2 instances after round-trip, got %d", len(decoded))
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
