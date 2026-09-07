package sqlite

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
	"github.com/google/go-cmp/cmp"
)

// noOpSecret has no commands so Await is a no-op subprocess (used for store-only tests).
var noOpSecret = &secrets.Secret{Id: "s1"}

func newTestRepo(t *testing.T, s secrets.Secrets) *SecretRespository {
	t.Helper()
	if s == nil {
		s = secrets.Secrets{"s1": noOpSecret}
	}
	ctx := context.Background()
	dbFile := filepath.Join(t.TempDir(), "store.db")
	repo, err := NewSecretRepository(ctx, dbFile, s, false, 256)
	if err != nil {
		t.Fatalf("NewSecretRepository: %v", err)
	}
	t.Cleanup(repo.Close)
	return repo
}

// createInstance starts a create operation and awaits completion.
func createInstance(t *testing.T, instances store.Instances, ctx context.Context, params executor.OperationParameters) *secrets.Instance {
	t.Helper()
	instance, err := instances.Create(ctx, params, discardStdio())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return awaitOperation(t, instances, ctx, instance.Id, instance.Status.OperationNumber)
}

func awaitOperation(t *testing.T, instances store.Instances, ctx context.Context, instanceId string, opNumber int) *secrets.Instance {
	t.Helper()
	_, completed, err := instances.Operations(instanceId).Await(ctx, opNumber)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	return completed
}

func discardStdio() command.Stdio {
	return command.Stdio{Stdout: io.Discard, Stderr: io.Discard}
}

// runOperation starts an update operation and awaits completion.
func runOperation(t *testing.T, instances store.Instances, ctx context.Context, instanceId string, op func(context.Context, string, executor.OperationParameters, command.Stdio) (*secrets.Instance, error), params executor.OperationParameters) *secrets.Instance {
	t.Helper()
	instance, err := op(ctx, instanceId, params, discardStdio())
	if err != nil {
		t.Fatalf("operation start: %v", err)
	}
	return awaitOperation(t, instances, ctx, instanceId, instance.Status.OperationNumber)
}

func TestNewSecretRepository(t *testing.T) {
	ctx := context.Background()
	dbFile := filepath.Join(t.TempDir(), "store.db")
	repo, err := NewSecretRepository(ctx, dbFile, secrets.Secrets{"s1": noOpSecret}, false, 256)
	if err != nil {
		t.Fatalf("NewSecretRepository: %v", err)
	}
	repo.Close()
}

func TestSecretRepository_List(t *testing.T) {
	want := secrets.Secrets{"s1": noOpSecret, "s2": {Id: "s2"}}
	repo := newTestRepo(t, want)
	ctx := context.Background()

	got, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !cmp.Equal(got, want, cmp.AllowUnexported(secrets.Secret{})) {
		t.Errorf("List:\n%s", cmp.Diff(want, got, cmp.AllowUnexported(secrets.Secret{})))
	}
}

func TestSecretRepository_Get(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()

	tests := []struct {
		name     string
		secretId string
		wantErr  bool
		wantId   string
	}{
		{"found", "s1", false, "s1"},
		{"not found", "missing", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := repo.Get(ctx, tt.secretId)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Get = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.Id != tt.wantId {
				t.Errorf("Get().Id = %q, want %q", got.Id, tt.wantId)
			}
		})
	}
}

func TestSecretRepository_Instances_Create_unknownSecret(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("nonexistent")

	_, err := instances.Create(ctx, executor.OperationParameters{Reason: "r", StartedBy: "u"}, discardStdio())
	if err == nil {
		t.Fatal("Create = nil, want error")
	}
}

func TestSecretRepository_Instances_returnsSameRepository(t *testing.T) {
	repo := newTestRepo(t, nil)
	if repo.Instances("s1") != repo.Instances("s1") {
		t.Fatal("Instances() must return the same repository so Await can wait on in-flight operations")
	}
}

func TestSecretRepository_Instances_AwaitAcrossLookups(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	started, err := repo.Instances("s1").Create(ctx, executor.OperationParameters{Reason: "r", StartedBy: "u"}, discardStdio())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	completed := awaitOperation(t, repo.Instances("s1"), ctx, started.Id, started.Status.OperationNumber)
	if completed.Status.CompletedAt == nil {
		t.Fatal("expected completedAt after Await from a separate Instances() lookup")
	}
}

func TestInstanceRepository_Create_stdinReachesSubprocess(t *testing.T) {
	out := filepath.Join(t.TempDir(), "captured")
	// Bash builtins only (no PATH); same idea as secrets that use echo in other tests.
	script := fmt.Sprintf(`read -r _stdin || :; printf '%%s' "$_stdin" > %q`, out)
	s := &secrets.Secret{
		Id:     "s1",
		Create: command.New(script, command.NewEnvironment(), ""),
	}
	repo := newTestRepo(t, secrets.Secrets{"s1": s})
	ctx := context.Background()
	instances := repo.Instances("s1")
	instance, err := instances.Create(ctx, executor.OperationParameters{Reason: "r", StartedBy: "user"}, command.Stdio{
		Stdin:  strings.NewReader("stdin-payload"),
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	awaitOperation(t, instances, ctx, instance.Id, instance.Status.OperationNumber)
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	if string(data) != "stdin-payload" {
		t.Fatalf("captured = %q, want stdin-payload", data)
	}
}

func TestInstanceRepository_Create_List_Get(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	created := createInstance(t, instances, ctx, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	if created.Id == "" {
		t.Error("Create returned instance with empty Id")
	}
	if created.Secret.Id != "s1" {
		t.Errorf("Create returned Secret.Id = %q", created.Secret.Id)
	}

	list, err := instances.List(ctx, 0, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d instances, want 1", len(list))
	}
	listed := list[created.Id]
	if listed == nil {
		t.Fatal("List missing created instance")
	}
	if listed.Id != created.Id {
		t.Errorf("List instance Id = %q", listed.Id)
	}

	got, err := instances.Get(ctx, created.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Id != created.Id {
		t.Errorf("Get Id = %q", got.Id)
	}
}

func TestInstanceRepository_Get_notFound(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	_, err := instances.Get(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Get = nil, want error")
	}
}

func TestInstanceRepository_GetActive(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	active, err := instances.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive (no active): %v", err)
	}
	if active != nil {
		t.Errorf("GetActive = %v, want nil", active)
	}

	created := createInstance(t, instances, ctx, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, instances, ctx, created.Id, instances.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	active, err = instances.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active == nil || active.Id != created.Id {
		t.Errorf("GetActive = %v, want instance %q", active, created.Id)
	}
}

func TestInstanceRepository_History(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	created := createInstance(t, instances, ctx, executor.OperationParameters{Reason: "create", StartedBy: "user"})

	ops, err := instances.Operations(created.Id).List(ctx, 0, 10)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("History len = %d, want 1", len(ops))
	}
	if ops[0].Name != secrets.Create {
		t.Errorf("History[0].Name = %s", ops[0].Name)
	}
}

func TestInstanceRepository_Activate_Deactivate(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	created := createInstance(t, instances, ctx, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	if created.Status.Name != secrets.Create {
		t.Errorf("Create returned instance with status %s, want %s", created.Status.Name, secrets.Create)
	}

	activated := runOperation(t, instances, ctx, created.Id, instances.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})
	active, _ := instances.GetActive(ctx)
	if active == nil || active.Id != created.Id {
		t.Errorf("after Activate, GetActive = %v", active)
	}
	if activated.Status.Name != secrets.Activate {
		t.Errorf("Activate returned instance with status %s, want %s", activated.Status.Name, secrets.Activate)
	}

	deactivated := runOperation(t, instances, ctx, created.Id, instances.Deactivate, executor.OperationParameters{Reason: "deactivate", StartedBy: "user"})
	active, _ = instances.GetActive(ctx)
	if active != nil {
		t.Errorf("after Deactivate, GetActive = %v, want nil", active)
	}
	if deactivated.Status.Name != secrets.Deactivate {
		t.Errorf("Deactivate returned instance with status %s, want %s", deactivated.Status.Name, secrets.Deactivate)
	}
}

func TestInstanceRepository_ExpectedOperationNumber(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	created := createInstance(t, instances, ctx, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, instances, ctx, created.Id, instances.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	// Instance is now at operation 2 (Create=1, Activate=2). Deactivate requires current op 2.
	expected := 2
	deactivated := runOperation(t, instances, ctx, created.Id, instances.Deactivate, executor.OperationParameters{Reason: "deact", StartedBy: "user", ExpectedOperationNumber: &expected})
	_ = deactivated

	// Instance is now at operation 3. Try Activate with expected 1 (wrong) - should fail.
	wrongExpected := 1
	_, err := instances.Activate(ctx, created.Id, executor.OperationParameters{Reason: "act", StartedBy: "user", ExpectedOperationNumber: &wrongExpected}, discardStdio())
	if err == nil {
		t.Fatal("Activate with mismatched ExpectedOperationNumber want error")
	}
	if err.Error() != "cannot activate when previous operation 3 does not match expected 1" {
		t.Errorf("unexpected error: %v", err)
	}

	// Same but Forced - should succeed
	started, err := instances.Activate(ctx, created.Id, executor.OperationParameters{Reason: "act", StartedBy: "user", ExpectedOperationNumber: &wrongExpected, Forced: true}, discardStdio())
	if err != nil {
		t.Fatalf("Activate with Forced should ignore ExpectedOperationNumber mismatch: %v", err)
	}
	awaitOperation(t, instances, ctx, started.Id, started.Status.OperationNumber)
}

func TestInstanceRepository_Create_validateReason(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	instance, err := instances.Create(ctx, executor.OperationParameters{Reason: "ok", StartedBy: "user"}, discardStdio())
	if err != nil {
		t.Fatalf("Create (short reason): %v", err)
	}
	awaitOperation(t, instances, ctx, instance.Id, instance.Status.OperationNumber)

	// maxReasonLen is 256 in newTestRepo
	longReason := string(make([]byte, 257))
	_, err = instances.Create(ctx, executor.OperationParameters{Reason: longReason, StartedBy: "user"}, discardStdio())
	if err == nil {
		t.Fatal("Create with too-long reason = nil, want error")
	}
}

func TestInstanceRepository_planPinnedAfterVersionBump(t *testing.T) {
	ctx := context.Background()
	marker := filepath.Join(t.TempDir(), "marker")
	env := command.NewEnvironment()
	cmd := func(script string) *command.Command {
		return command.New(script, env, "")
	}
	v1 := &secrets.Secret{
		Id:       "s1",
		Version:  1,
		Create:   cmd("true"),
		Activate: cmd("true"),
		Test:     cmd(fmt.Sprintf(`printf v1 > %q`, marker)),
	}
	v2 := &secrets.Secret{
		Id:       "s1",
		Version:  2,
		Create:   cmd("true"),
		Activate: cmd("true"),
		Test:     cmd(fmt.Sprintf(`printf v2 > %q`, marker)),
	}

	repo := newTestRepo(t, secrets.Secrets{"s1": v1})
	instances := repo.Instances("s1")

	created := createInstance(t, instances, ctx, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, instances, ctx, created.Id, instances.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	repo.secrets["s1"] = v2
	if err := syncPlanRevisions(ctx, repo.db, repo.secrets); err != nil {
		t.Fatalf("syncPlanRevisions after bump: %v", err)
	}

	runOperation(t, instances, ctx, created.Id, instances.Test, executor.OperationParameters{Reason: "test", StartedBy: "user"})

	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(data) != "v1" {
		t.Fatalf("Test command wrote %q, want v1 (instance should use revision v1, not v2)", data)
	}

	got, err := instances.Get(ctx, created.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Secret.Version != 1 {
		t.Errorf("Get().Secret.Version = %d, want 1", got.Secret.Version)
	}
}
