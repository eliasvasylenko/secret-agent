package secrets

import (
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
			{Name: "a", Version: 1, Create: command.New("echo a", nil, "")},
			{Name: "b", Version: 1, Create: command.New("echo b", nil, "")},
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
			{Name: "x", Version: 1},
			{Name: "x", Version: 1},
		})
		if err == nil {
			t.Fatal("expected error for duplicate name")
		}
		if fmt.Sprint(err) != "Secret name 'x' must be unique" {
			t.Errorf("expected duplicate name error, got %v", err)
		}
	})
	t.Run("version below 1 rejected", func(t *testing.T) {
		for _, mv := range []int{-1, 0} {
			_, err := New([]*Secret{{Name: "x", Version: mv}})
			if err == nil {
				t.Fatalf("Version %d: expected error", mv)
			}
			if fmt.Sprint(err) != "Secret 'x' version must be >= 1" {
				t.Errorf("Version %d: got error %v", mv, err)
			}
		}
	})
}

func TestSecrets_MarshalJSON(t *testing.T) {
	secrets := Secrets{
		"friend": {Name: "friend", Version: 1, Create: command.New("echo hello", nil, "")},
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

func TestLoadPlans(t *testing.T) {
	friend := &Secret{
		Name:    "friend",
		Version: 1,
		Create:  command.New("echo hello friend", nil, ""),
	}
	dbCreds := &Secret{
		Name:       "db-creds",
		Version:    1,
		Create:     command.New("openssl rand -base64 32", nil, ""),
		Destroy:    command.New("rm -f /etc/enrypted-creds/$NAME/$ID.cred", nil, ""),
		Activate:   command.New("cp -f /etc/enrypted-creds/$NAME/$ID.cred /etc/enrypted-creds/service.cred", nil, ""),
		Deactivate: command.New("rm -f /etc/enrypted-creds/service.cred", nil, ""),
		Test:       command.New("ssh host -csecret-agent test $NAME $ID", nil, ""),
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
	data := `[{"id":"i1","secret":{"name":"s1","version":1},"status":{"operationNumber":1,"name":"create"}}]`
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
	if instances["i1"].Secret.Version != 1 {
		t.Errorf("secret.version = %d, want 1", instances["i1"].Secret.Version)
	}
}

func TestInstances_MarshalJSON(t *testing.T) {
	instances := Instances{
		"id1": {Id: "id1", Secret: Secret{Name: "s1", Version: 1}, Status: Status{OperationNumber: 2}},
		"id2": {Id: "id2", Secret: Secret{Name: "s2", Version: 1}, Status: Status{OperationNumber: 1}},
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
