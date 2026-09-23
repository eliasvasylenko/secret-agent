package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/mocks"
	sec "github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/go-cmp/cmp"
)

// stubKongContext implements kongContext for tests.
type stubKongContext struct {
	command string
}

func (s stubKongContext) Command() string { return s.command }
func (s stubKongContext) FatalIfErrorf(err error, _ ...any) {
	if err != nil {
		panic(err)
	}
}

func expectCatalog(mockBackend *mocks.MockBackend, mockCatalog *mocks.MockCatalog) {
	mocks.Expect(&mockBackend.Mock, mockBackend.Catalog, func() backend.Catalog {
		return mockCatalog
	})
}

func TestRun_secrets(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockSecrets := &mocks.MockSecrets{}
	defer mockSecrets.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
	mocks.Expect(&mockSecrets.Mock, mockSecrets.List, func(ctx context.Context) (sec.Secrets, error) {
		return sec.Secrets{"s1": {Id: "s1"}}, nil
	})

	cli := &CLI{
		ctx:   stubKongContext{command: "secrets"},
		agent: mockBackend,
	}
	stdout := captureStdout(t, func() {
		cli.Run(context.Background())
	})
	if !bytes.Contains(stdout, []byte(`"s1"`)) {
		t.Errorf("stdout should contain secret s1, got %s", stdout)
	}
}

func TestRun_secret(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockSecrets := &mocks.MockSecrets{}
	defer mockSecrets.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
	want := &sec.Secret{Id: "my-secret", Version: 1}
	mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(ctx context.Context, secretId string) (*sec.Secret, error) {
		if secretId != "my-secret" {
			t.Errorf("Get called with secretId=%q, want my-secret", secretId)
		}
		return want, nil
	})

	cli := &CLI{
		ctx:    stubKongContext{command: "secret <secret-id>"},
		agent:  mockBackend,
		Secret: Secret{SecretID: "my-secret"},
	}
	stdout := captureStdout(t, func() {
		cli.Run(context.Background())
	})
	var got sec.Secret
	if err := json.Unmarshal(stdout, &got); err != nil {
		t.Fatalf("stdout should be valid JSON: %v\noutput: %s", err, stdout)
	}
	expected := sec.Secret{Id: "my-secret", Version: 1}
	if !cmp.Equal(got, expected) {
		t.Errorf("stdout secret:\n%s", cmp.Diff(expected, got))
	}
}

func TestRun_instances(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.List, func(ctx context.Context, secretId *string, from int, to int) (sec.Instances, error) {
		if secretId == nil || *secretId != "my-secret" {
			t.Errorf("List secretId = %v, want my-secret", secretId)
		}
		if from != 0 || to != 10 {
			t.Errorf("List called with from=%d to=%d, want 0 10", from, to)
		}
		return sec.Instances{}, nil
	})

	cli := &CLI{
		ctx:       stubKongContext{command: "instances <secret-id>"},
		agent:     mockBackend,
		Instances: Instances{SecretID: "my-secret", Bounds: Bounds{From: 0, To: 10}},
	}
	stdout := captureStdout(t, func() {
		cli.Run(context.Background())
	})
	var got sec.Instances
	if err := json.Unmarshal(stdout, &got); err != nil {
		t.Fatalf("stdout should be valid JSON: %v\noutput: %s", err, stdout)
	}
	want := sec.Instances{}
	if !cmp.Equal(got, want) {
		t.Errorf("stdout instances:\n%s", cmp.Diff(want, got))
	}
}

func captureStdout(t *testing.T, f func()) []byte {
	t.Helper()
	old := os.Stdout
	defer func() { os.Stdout = old }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { w.Close() }()
	os.Stdout = w
	f()
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
