package sqlite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/ops"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/go-cmp/cmp"
)

type noopProposer struct{}

func (noopProposer) Propose(context.Context, secrets.OperationName, executor.OperationParameters) error {
	return nil
}

// noOpSecret has no commands so Run completes immediately (used for store-only tests).
var noOpSecret = &secrets.Secret{Id: "s1"}

func newTestBackend(t *testing.T, s secrets.Secrets) *Backend {
	t.Helper()
	if s == nil {
		s = secrets.Secrets{"s1": noOpSecret}
	}
	ctx := context.Background()
	dbFile := filepath.Join(t.TempDir(), "backend.db")
	backend, err := Open(ctx, dbFile, s, false, 256)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(backend.Close)
	return backend
}

func discardStdio() command.Stdio {
	return command.Stdio{Stdout: io.Discard, Stderr: io.Discard}
}

func createInstance(t *testing.T, backend *Backend, secretId string, params executor.OperationParameters) *secrets.Instance {
	t.Helper()
	ctx := context.Background()
	got, err := ops.Create(ctx, backend.Runner(secretId), params, noopProposer{}, discardStdio())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return got
}

func runOperation(
	t *testing.T,
	repo *Backend,
	secretId, instanceId string,
	op func(context.Context, backend.Runner, string, executor.OperationParameters, backend.Proposer, command.Stdio) (*secrets.Instance, error),
	params executor.OperationParameters,
) *secrets.Instance {
	t.Helper()
	ctx := context.Background()
	got, err := op(ctx, repo.Runner(secretId), instanceId, params, noopProposer{}, discardStdio())
	if err != nil {
		t.Fatalf("operation: %v", err)
	}
	return got
}

func TestOpen(t *testing.T) {
	ctx := context.Background()
	dbFile := filepath.Join(t.TempDir(), "backend.db")
	backend, err := Open(ctx, dbFile, secrets.Secrets{"s1": noOpSecret}, false, 256)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	backend.Close()
}

func TestSecretRepository_List(t *testing.T) {
	want := secrets.Secrets{"s1": noOpSecret, "s2": {Id: "s2"}}
	repo := newTestBackend(t, want)
	ctx := context.Background()

	got, err := repo.Catalog().Secrets().List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !cmp.Equal(got, want, cmp.AllowUnexported(secrets.Secret{})) {
		t.Errorf("List:\n%s", cmp.Diff(want, got, cmp.AllowUnexported(secrets.Secret{})))
	}
}

func TestSecretRepository_Get(t *testing.T) {
	repo := newTestBackend(t, nil)
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
			got, err := repo.Catalog().Secrets().Get(ctx, tt.secretId)
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

func TestRunner_Create_unknownSecret(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()

	_, err := ops.Create(ctx, repo.Runner("nonexistent"), executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, discardStdio())
	if err == nil {
		t.Fatal("Create = nil, want error")
	}
}

func TestRunner_WaitIdempotent(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	runner := repo.Runner("s1")

	_, handle, err := runner.Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, discardStdio())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	first, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	second, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("wait again: %v", err)
	}
	if first.Id != second.Id {
		t.Fatalf("wait returned different instances: %q vs %q", first.Id, second.Id)
	}
	if first.Status.CompletedAt == nil {
		t.Fatal("expected completedAt after wait")
	}
}

func TestRunner_Handle_CancelStopsExecute(t *testing.T) {
	s := &secrets.Secret{
		Id:     "s1",
		Create: command.New(`read -r _`, command.NewEnvironment(), ""),
	}
	repo := newTestBackend(t, secrets.Secrets{"s1": s})
	ctx := context.Background()
	runner := repo.Runner("s1")

	stdinR, stdinW := io.Pipe()
	t.Cleanup(func() { _ = stdinR.Close() })
	t.Cleanup(func() { _ = stdinW.Close() })

	_, handle, err := runner.Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, command.Stdio{
		Stdin:  stdinR,
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if err := handle.Cancel(ctx); err != nil {
		t.Fatalf("Cancel: %v", err)
	}

	final, err := handle.Wait(ctx)
	if err == nil {
		t.Fatal("Wait after Cancel = nil, want error")
	}
	if final == nil || final.Status.FailedAt == nil {
		t.Fatal("expected failedAt after Cancel")
	}
}

func TestRunner_WaitAbandonThenRejoin(t *testing.T) {
	s := &secrets.Secret{
		Id:     "s1",
		Create: command.New(`read -t 2 _ || exit 0`, command.NewEnvironment(), ""),
	}
	repo := newTestBackend(t, secrets.Secrets{"s1": s})
	ctx := context.Background()
	runner := repo.Runner("s1")

	stdinR, stdinW := io.Pipe()
	t.Cleanup(func() { _ = stdinR.Close() })
	t.Cleanup(func() { _ = stdinW.Close() })

	_, handle, err := runner.Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, command.Stdio{
		Stdin:  stdinR,
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	abandonCtx, stop := context.WithTimeout(ctx, 1*time.Nanosecond)
	defer stop()
	_, err = handle.Wait(abandonCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("abandon Wait err = %v, want DeadlineExceeded", err)
	}

	final, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("rejoin Wait: %v", err)
	}
	if final.Status.CompletedAt == nil {
		t.Fatal("expected completedAt after rejoin wait")
	}
}

func TestRunner_Create_stdinReachesSubprocess(t *testing.T) {
	out := filepath.Join(t.TempDir(), "captured")
	script := fmt.Sprintf(`read -r _stdin || :; printf '%%s' "$_stdin" > %q`, out)
	s := &secrets.Secret{
		Id:     "s1",
		Create: command.New(script, command.NewEnvironment(), ""),
	}
	repo := newTestBackend(t, secrets.Secrets{"s1": s})
	ctx := context.Background()

	_, err := ops.Create(ctx, repo.Runner("s1"), executor.OperationParameters{Reason: "r", StartedBy: "user"}, noopProposer{}, command.Stdio{
		Stdin:  strings.NewReader("stdin-payload"),
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read captured file: %v", err)
	}
	if string(data) != "stdin-payload" {
		t.Fatalf("captured = %q, want stdin-payload", data)
	}
}

func TestInstances_Create_List_Get(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"
	instances := repo.Catalog().Instances()

	created := createInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	if created.Id == "" {
		t.Error("Create returned instance with empty Id")
	}
	if created.Secret.Id != secretId {
		t.Errorf("Create returned Secret.Id = %q", created.Secret.Id)
	}

	list, err := instances.List(ctx, &secretId, 0, 10)
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

func TestInstances_Get_notFound(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()

	_, err := repo.Catalog().Instances().Get(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Get = nil, want error")
	}
}

func TestInstances_GetActive(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"
	instances := repo.Catalog().Instances()

	active, err := instances.GetActive(ctx, secretId)
	if err != nil {
		t.Fatalf("GetActive (no active): %v", err)
	}
	if active != nil {
		t.Errorf("GetActive = %v, want nil", active)
	}

	created := createInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, repo, secretId, created.Id, ops.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	active, err = instances.GetActive(ctx, secretId)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active == nil || active.Id != created.Id {
		t.Errorf("GetActive = %v, want instance %q", active, created.Id)
	}
}

func TestOperations_List(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"

	created := createInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})

	opsList, err := repo.Catalog().Operations().List(ctx, &secretId, &created.Id, 0, 10)
	if err != nil {
		t.Fatalf("Operations.List: %v", err)
	}
	if len(opsList) != 1 {
		t.Fatalf("Operations.List len = %d, want 1", len(opsList))
	}
	if opsList[0].Name != secrets.Create {
		t.Errorf("Operations.List[0].Name = %s", opsList[0].Name)
	}
}

func TestRunner_Activate_Deactivate(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"
	instances := repo.Catalog().Instances()

	created := createInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	if created.Status.Name != secrets.Create {
		t.Errorf("Create returned instance with status %s, want %s", created.Status.Name, secrets.Create)
	}

	activated := runOperation(t, repo, secretId, created.Id, ops.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})
	active, _ := instances.GetActive(ctx, secretId)
	if active == nil || active.Id != created.Id {
		t.Errorf("after Activate, GetActive = %v", active)
	}
	if activated.Status.Name != secrets.Activate {
		t.Errorf("Activate returned instance with status %s, want %s", activated.Status.Name, secrets.Activate)
	}

	deactivated := runOperation(t, repo, secretId, created.Id, ops.Deactivate, executor.OperationParameters{Reason: "deactivate", StartedBy: "user"})
	active, _ = instances.GetActive(ctx, secretId)
	if active != nil {
		t.Errorf("after Deactivate, GetActive = %v, want nil", active)
	}
	if deactivated.Status.Name != secrets.Deactivate {
		t.Errorf("Deactivate returned instance with status %s, want %s", deactivated.Status.Name, secrets.Deactivate)
	}
}

func TestRunner_ExpectedOperationNumber(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"

	created := createInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, repo, secretId, created.Id, ops.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	expected := 2
	runOperation(t, repo, secretId, created.Id, ops.Deactivate, executor.OperationParameters{Reason: "deact", StartedBy: "user", ExpectedOperationNumber: &expected})

	wrongExpected := 1
	_, err := ops.Activate(ctx, repo.Runner(secretId), created.Id, executor.OperationParameters{Reason: "act", StartedBy: "user", ExpectedOperationNumber: &wrongExpected}, noopProposer{}, discardStdio())
	if err == nil {
		t.Fatal("Activate with mismatched ExpectedOperationNumber want error")
	}
	if err.Error() != "cannot activate when previous operation 3 does not match expected 1" {
		t.Errorf("unexpected error: %v", err)
	}

	_, handle, err := repo.Runner(secretId).Run(ctx, secrets.Activate, created.Id, executor.OperationParameters{Reason: "act", StartedBy: "user", ExpectedOperationNumber: &wrongExpected, Forced: true}, noopProposer{}, discardStdio())
	if err != nil {
		t.Fatalf("Activate with Forced should ignore ExpectedOperationNumber mismatch: %v", err)
	}
	completed, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if completed.Id != created.Id {
		t.Fatalf("completed Id = %q, want %q", completed.Id, created.Id)
	}
}

func TestRunner_Create_validateReason(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"

	createInstance(t, repo, secretId, executor.OperationParameters{Reason: "ok", StartedBy: "user"})

	longReason := string(make([]byte, 257))
	_, err := ops.Create(ctx, repo.Runner(secretId), executor.OperationParameters{Reason: longReason, StartedBy: "user"}, noopProposer{}, discardStdio())
	if err == nil {
		t.Fatal("Create with too-long reason = nil, want error")
	}
}

func TestRunner_planPinnedAfterVersionBump(t *testing.T) {
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

	repo := newTestBackend(t, secrets.Secrets{"s1": v1})
	secretId := "s1"

	created := createInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, repo, secretId, created.Id, ops.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	repo.repo.secrets["s1"] = v2
	if err := syncPlanRevisions(ctx, repo.repo.db, repo.repo.secrets); err != nil {
		t.Fatalf("syncPlanRevisions after bump: %v", err)
	}

	runOperation(t, repo, secretId, created.Id, ops.Test, executor.OperationParameters{Reason: "test", StartedBy: "user"})

	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(data) != "v1" {
		t.Fatalf("Test command wrote %q, want v1 (instance should use revision v1, not v2)", data)
	}

	got, err := repo.Catalog().Instances().Get(ctx, created.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Secret.Version != 1 {
		t.Errorf("Get().Secret.Version = %d, want 1", got.Secret.Version)
	}
}
