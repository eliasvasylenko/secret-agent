package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/mocks"
	sec "github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
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

func TestRun_secrets(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockList := func(ctx context.Context) (sec.Secrets, error) {
		return sec.Secrets{"s1": {Name: "s1"}}, nil
	}
	mocks.Expect(&mockStore.Mock, mockStore.List, mockList)

	cli := &CLI{
		ctx:         stubKongContext{command: "secrets"},
		secretStore: mockStore,
	}
	stdout := captureStdout(t, func() {
		cli.Run(context.Background())
	})
	if !bytes.Contains(stdout, []byte(`"s1"`)) {
		t.Errorf("stdout should contain secret s1, got %s", stdout)
	}
}

func TestRun_secret(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	want := &sec.Secret{Name: "my-secret"}
	mockGet := func(ctx context.Context, secretId string) (*sec.Secret, error) {
		if secretId != "my-secret" {
			t.Errorf("Get called with secretId=%q, want my-secret", secretId)
		}
		return want, nil
	}
	mocks.Expect(&mockStore.Mock, mockStore.Get, mockGet)

	cli := &CLI{
		ctx:         stubKongContext{command: "secret <secret-id>"},
		secretStore: mockStore,
		Secret:      Secret{SecretID: "my-secret"},
	}
	stdout := captureStdout(t, func() {
		cli.Run(context.Background())
	})
	var got sec.Secret
	if err := json.Unmarshal(stdout, &got); err != nil {
		t.Fatalf("stdout should be valid JSON: %v\noutput: %s", err, stdout)
	}
	expected := sec.Secret{Name: "my-secret"}
	if !cmp.Equal(got, expected) {
		t.Errorf("stdout secret:\n%s", cmp.Diff(expected, got))
	}
}

func TestRun_instances(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	instancesReturn := func(secretId string) store.Instances {
		if secretId != "my-secret" {
			t.Errorf("Instances called with secretId=%q, want my-secret", secretId)
		}
		return mockInstances
	}
	mockList := func(ctx context.Context, from int, to int) (sec.Instances, error) {
		if from != 0 || to != 10 {
			t.Errorf("List called with from=%d to=%d, want 0 10", from, to)
		}
		return sec.Instances{}, nil
	}
	mocks.Expect(&mockStore.Mock, mockStore.Instances, instancesReturn)
	mocks.Expect(&mockInstances.Mock, mockInstances.List, mockList)

	cli := &CLI{
		ctx:         stubKongContext{command: "instances <secret-id>"},
		secretStore: mockStore,
		Instances:   Instances{SecretID: "my-secret", Bounds: Bounds{From: 0, To: 10}},
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
