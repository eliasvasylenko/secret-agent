package sqlite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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

func (noopProposer) Propose(context.Context, string, secrets.OperationName, executor.OperationParameters, io.ReadWriteCloser) error {
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

func discardFiles() command.Files {
	return command.Files{Tty: command.NoTty}
}

func stdinFile(t *testing.T, s string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err := w.WriteString(s); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return r
}

func mustCreateInstance(t *testing.T, backend *Backend, secretId string, params executor.OperationParameters) *secrets.Instance {
	t.Helper()
	ctx := context.Background()
	got, err := ops.Create(ctx, backend.Runner(secretId), params, noopProposer{}, discardFiles())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return got
}

func runOperation(
	t *testing.T,
	repo *Backend,
	secretId, instanceId string,
	op func(context.Context, backend.Runner, string, executor.OperationParameters, backend.Proposer, command.Files) (*secrets.Instance, error),
	params executor.OperationParameters,
) *secrets.Instance {
	t.Helper()
	ctx := context.Background()
	got, err := op(ctx, repo.Runner(secretId), instanceId, params, noopProposer{}, discardFiles())
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
				var notFound *backend.SecretNotFoundError
				if !errors.As(err, &notFound) {
					t.Fatalf("Get = %v, want SecretNotFoundError", err)
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

	_, err := ops.Create(ctx, repo.Runner("nonexistent"), executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, discardFiles())
	if err == nil {
		t.Fatal("Create = nil, want error")
	}
	var notFound *backend.SecretNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("Create = %v, want SecretNotFoundError", err)
	}
}

func TestRunner_WaitIdempotent(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	runner := repo.Runner("s1")

	_, handle, err := runner.Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, discardFiles())
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
	if first.Operation.CompletedAt == nil {
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

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdinR.Close() })
	t.Cleanup(func() { _ = stdinW.Close() })

	_, handle, err := runner.Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, command.Files{Fds: []*os.File{stdinR}, Tty: command.NoTty})
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
	if final == nil || final.Operation.FailedAt == nil {
		t.Fatal("expected failedAt after Cancel")
	}
	if final.State.Name != secrets.Proposed {
		t.Errorf("state = %s, want %s", final.State.Name, secrets.Proposed)
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

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdinR.Close() })
	t.Cleanup(func() { _ = stdinW.Close() })

	_, handle, err := runner.Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r", StartedBy: "u"}, noopProposer{}, command.Files{Fds: []*os.File{stdinR}, Tty: command.NoTty})
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
	if final.Operation.CompletedAt == nil {
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

	_, err := ops.Create(ctx, repo.Runner("s1"), executor.OperationParameters{Reason: "r", StartedBy: "user"}, noopProposer{}, command.Files{Fds: []*os.File{stdinFile(t, "stdin-payload")}, Tty: command.NoTty})
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

	created := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
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

func TestInstances_ListOrdersByCreatedAtThenId(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"
	instances := repo.Catalog().Instances()

	created := []*secrets.Instance{
		mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "a", StartedBy: "user"}),
		mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "b", StartedBy: "user"}),
		mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "c", StartedBy: "user"}),
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for i, instance := range created {
		if _, err := repo.repo.db.Exec(`UPDATE instance SET opCreatedAt = ? WHERE id = ?`, base.Add(time.Duration(i)*time.Minute), instance.Id); err != nil {
			t.Fatal(err)
		}
	}

	page := func(from, to int) string {
		t.Helper()
		list, err := instances.List(ctx, &secretId, from, to)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 1 {
			t.Fatalf("List(%d, %d) returned %d instances, want 1", from, to, len(list))
		}
		for id := range list {
			return id
		}
		return ""
	}
	// created[2] is the newest.
	if got := page(0, 1); got != created[2].Id {
		t.Errorf("first page = %s, want newest %s", got, created[2].Id)
	}
	if got := page(1, 2); got != created[1].Id {
		t.Errorf("second page = %s, want %s", got, created[1].Id)
	}
	if got := page(2, 3); got != created[0].Id {
		t.Errorf("third page = %s, want oldest %s", got, created[0].Id)
	}

	for _, instance := range created {
		if _, err := repo.repo.db.Exec(`UPDATE instance SET opCreatedAt = ? WHERE id = ?`, base, instance.Id); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{created[0].Id, created[1].Id, created[2].Id}
	slices.Sort(ids)
	if got := page(0, 1); got != ids[0] {
		t.Errorf("tie page = %s, want smaller id %s", got, ids[0])
	}
	if got := page(1, 2); got != ids[1] {
		t.Errorf("tie page = %s, want %s", got, ids[1])
	}
}

func TestInstances_Get_notFound(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()

	_, err := repo.Catalog().Instances().Get(ctx, "nonexistent-id")
	if err == nil {
		t.Fatal("Get = nil, want error")
	}
	var notFound *backend.InstanceNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("Get = %v, want InstanceNotFoundError", err)
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

	created := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, repo, secretId, created.Id, ops.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	active, err = instances.GetActive(ctx, secretId)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active == nil || active.Id != created.Id {
		t.Errorf("GetActive = %v, want instance %q", active, created.Id)
	}
}

func TestRunner_Snapshot(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()

	created := mustCreateInstance(t, repo, "s1", executor.OperationParameters{Reason: "create", StartedBy: "user"})
	if created.Operation.Id != "" {
		t.Errorf("Operation.Id = %q, want empty", created.Operation.Id)
	}
	if created.State.Name != secrets.Created || created.Operation.Name != secrets.Create {
		t.Errorf("state %s operation %s, want create", created.State.Name, created.Operation.Name)
	}
	if created.Operation.CreatedBy != "user" || created.Operation.StartedBy != "user" {
		t.Errorf("createdBy %q startedBy %q", created.Operation.CreatedBy, created.Operation.StartedBy)
	}
	if created.Revision != 2 {
		t.Errorf("Revision = %d, want 2 (start then complete)", created.Revision)
	}
	if created.State.EnteredAt.IsZero() || created.Operation.CompletedAt == nil || !created.State.EnteredAt.Equal(*created.Operation.CompletedAt) {
		t.Errorf("state at %v completed %v", created.State.EnteredAt, created.Operation.CompletedAt)
	}

	got, err := repo.Catalog().Instances().Get(ctx, created.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Revision != created.Revision || got.State.Name != secrets.Created {
		t.Errorf("reloaded = %+v", got)
	}
}

func TestRunner_Activate_Deactivate(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"
	instances := repo.Catalog().Instances()

	created := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	if created.State.Name != secrets.Created {
		t.Errorf("Create returned instance in state %s, want %s", created.State.Name, secrets.Created)
	}

	activated := runOperation(t, repo, secretId, created.Id, ops.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})
	active, _ := instances.GetActive(ctx, secretId)
	if active == nil || active.Id != created.Id {
		t.Errorf("after Activate, GetActive = %v", active)
	}
	if activated.State.Name != secrets.Activated {
		t.Errorf("Activate returned instance in state %s, want %s", activated.State.Name, secrets.Activated)
	}

	deactivated := runOperation(t, repo, secretId, created.Id, ops.Deactivate, executor.OperationParameters{Reason: "deactivate", StartedBy: "user"})
	active, _ = instances.GetActive(ctx, secretId)
	if active != nil {
		t.Errorf("after Deactivate, GetActive = %v, want nil", active)
	}
	if deactivated.State.Name != secrets.Deactivated {
		t.Errorf("Deactivate returned instance in state %s, want %s", deactivated.State.Name, secrets.Deactivated)
	}
}

func TestRunner_Deactivate_notActive(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	created := mustCreateInstance(t, repo, "s1", executor.OperationParameters{Reason: "create", StartedBy: "user"})
	_, err := ops.Deactivate(ctx, repo.Runner("s1"), created.Id, executor.OperationParameters{Reason: "deact", StartedBy: "user"}, noopProposer{}, discardFiles())
	var notActive *backend.InstanceNotActiveError
	if err == nil || !errors.As(err, &notActive) {
		t.Fatalf("Deactivate = %v, want InstanceNotActiveError", err)
	}
}

func TestRunner_Activate_alreadyActive(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	first := mustCreateInstance(t, repo, "s1", executor.OperationParameters{Reason: "create", StartedBy: "user"})
	second := mustCreateInstance(t, repo, "s1", executor.OperationParameters{Reason: "create2", StartedBy: "user"})
	runOperation(t, repo, "s1", first.Id, ops.Activate, executor.OperationParameters{Reason: "act", StartedBy: "user"})
	_, err := ops.Activate(ctx, repo.Runner("s1"), second.Id, executor.OperationParameters{Reason: "act2", StartedBy: "user"}, noopProposer{}, discardFiles())
	var already *backend.InstanceAlreadyActiveError
	if err == nil || !errors.As(err, &already) || already.ActiveId != first.Id {
		t.Fatalf("Activate = %v, want InstanceAlreadyActiveError for %s", err, first.Id)
	}
}

func TestRunner_Destroy_refusesWhileActive(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"
	instances := repo.Catalog().Instances()

	created := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	destroyed := runOperation(t, repo, secretId, created.Id, ops.Destroy, executor.OperationParameters{Reason: "destroy-created", StartedBy: "user"})
	if destroyed.State.Name != secrets.Destroyed {
		t.Errorf("destroy never-active state = %s, want %s", destroyed.State.Name, secrets.Destroyed)
	}

	active := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create2", StartedBy: "user"})
	other := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create3", StartedBy: "user"})
	runOperation(t, repo, secretId, active.Id, ops.Activate, executor.OperationParameters{Reason: "act", StartedBy: "user"})

	_, err := ops.Destroy(ctx, repo.Runner(secretId), active.Id, executor.OperationParameters{Reason: "nope", StartedBy: "user"}, noopProposer{}, discardFiles())
	var already *backend.InstanceAlreadyActiveError
	if err == nil || !errors.As(err, &already) || already.ActiveId != active.Id {
		t.Fatalf("Destroy active = %v, want InstanceAlreadyActiveError for %s", err, active.Id)
	}
	got, getErr := instances.GetActive(ctx, secretId)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if got == nil || got.Id != active.Id || got.State.Name != secrets.Activated {
		t.Fatalf("GetActive after refused destroy = %+v, want activated %s", got, active.Id)
	}

	runOperation(t, repo, secretId, other.Id, ops.Destroy, executor.OperationParameters{Reason: "destroy-other", StartedBy: "user"})
	got, getErr = instances.GetActive(ctx, secretId)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if got == nil || got.Id != active.Id {
		t.Fatalf("GetActive after destroying sibling = %+v, want %s", got, active.Id)
	}

	runOperation(t, repo, secretId, active.Id, ops.Deactivate, executor.OperationParameters{Reason: "deact", StartedBy: "user"})
	runOperation(t, repo, secretId, active.Id, ops.Destroy, executor.OperationParameters{Reason: "destroy-deactivated", StartedBy: "user"})
	got, getErr = instances.GetActive(ctx, secretId)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if got != nil {
		t.Fatalf("GetActive after destroy of deactivated = %+v, want nil", got)
	}
}

func TestRunner_Destroy_forcedClearsActive(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	created := mustCreateInstance(t, repo, "s1", executor.OperationParameters{Reason: "create", StartedBy: "user"})
	runOperation(t, repo, "s1", created.Id, ops.Activate, executor.OperationParameters{Reason: "act", StartedBy: "user"})

	_, handle, err := repo.Runner("s1").Run(ctx, secrets.Destroy, created.Id, executor.OperationParameters{Reason: "force", StartedBy: "user", Forced: true}, noopProposer{}, discardFiles())
	if err != nil {
		t.Fatalf("forced Destroy: %v", err)
	}
	got, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if got.State.Name != secrets.Destroyed {
		t.Errorf("state = %s, want %s", got.State.Name, secrets.Destroyed)
	}
	active, err := repo.Catalog().Instances().GetActive(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Fatalf("GetActive after forced destroy = %+v, want nil", active)
	}
}

func TestRunner_ExpectedRevision(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"

	created := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
	activated := runOperation(t, repo, secretId, created.Id, ops.Activate, executor.OperationParameters{Reason: "activate", StartedBy: "user"})

	runOperation(t, repo, secretId, created.Id, ops.Deactivate, executor.OperationParameters{Reason: "deact", StartedBy: "user", ExpectedRevision: &activated.Revision})

	wrongExpected := 1
	_, err := ops.Activate(ctx, repo.Runner(secretId), created.Id, executor.OperationParameters{Reason: "act", StartedBy: "user", ExpectedRevision: &wrongExpected}, noopProposer{}, discardFiles())
	if err == nil {
		t.Fatal("Activate with mismatched ExpectedRevision want error")
	}
	deactivated, getErr := repo.Catalog().Instances().Get(ctx, created.Id)
	if getErr != nil {
		t.Fatal(getErr)
	}
	wantErr := fmt.Sprintf("cannot activate when revision %d does not match expected 1", deactivated.Revision)
	if err.Error() != wantErr {
		t.Errorf("unexpected error: %v", err)
	}
	var mismatch *backend.RevisionMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("Activate = %v, want RevisionMismatchError", err)
	}

	_, handle, err := repo.Runner(secretId).Run(ctx, secrets.Activate, created.Id, executor.OperationParameters{Reason: "act", StartedBy: "user", ExpectedRevision: &wrongExpected, Forced: true}, noopProposer{}, discardFiles())
	if err != nil {
		t.Fatalf("Activate with Forced should ignore ExpectedRevision mismatch: %v", err)
	}
	completed, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if completed.Id != created.Id {
		t.Fatalf("completed Id = %q, want %q", completed.Id, created.Id)
	}
}

func TestRunner_FailureLeavesState(t *testing.T) {
	s := &secrets.Secret{
		Id:       "s1",
		Activate: command.New(`exit 1`, command.NewEnvironment(), ""),
	}
	repo := newTestBackend(t, secrets.Secrets{"s1": s})
	ctx := context.Background()

	created := mustCreateInstance(t, repo, "s1", executor.OperationParameters{Reason: "create", StartedBy: "user"})
	_, err := ops.Activate(ctx, repo.Runner("s1"), created.Id, executor.OperationParameters{Reason: "act", StartedBy: "user"}, noopProposer{}, discardFiles())
	if err == nil {
		t.Fatal("Activate = nil, want script error")
	}

	got, getErr := repo.Catalog().Instances().Get(ctx, created.Id)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if got.State.Name != secrets.Created {
		t.Errorf("state = %s, want %s", got.State.Name, secrets.Created)
	}
	if got.Operation.Name != secrets.Activate || got.Operation.FailedAt == nil {
		t.Errorf("operation = %+v, want failed activate", got.Operation)
	}
	if got.Revision != created.Revision+2 {
		t.Errorf("Revision = %d, want %d", got.Revision, created.Revision+2)
	}
	active, _ := repo.Catalog().Instances().GetActive(ctx, "s1")
	if active != nil {
		t.Errorf("GetActive = %v, want nil after failed activate", active)
	}

	_, err = ops.Deactivate(ctx, repo.Runner("s1"), created.Id, executor.OperationParameters{Reason: "deact", StartedBy: "user"}, noopProposer{}, discardFiles())
	var incomplete *backend.IncompleteOperationError
	if err == nil || !errors.As(err, &incomplete) || !strings.Contains(err.Error(), "cannot deactivate") {
		t.Fatalf("Deactivate = %v, want IncompleteOperationError", err)
	}

	_, err = ops.Activate(ctx, repo.Runner("s1"), created.Id, executor.OperationParameters{Reason: "retry", StartedBy: "user"}, noopProposer{}, discardFiles())
	if err == nil || strings.Contains(err.Error(), "cannot activate") {
		t.Fatalf("retry Activate = %v, want the script error", err)
	}
}

func TestRunner_Create_validateReason(t *testing.T) {
	repo := newTestBackend(t, nil)
	ctx := context.Background()
	secretId := "s1"

	mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "ok", StartedBy: "user"})

	longReason := string(make([]byte, 257))
	_, err := ops.Create(ctx, repo.Runner(secretId), executor.OperationParameters{Reason: longReason, StartedBy: "user"}, noopProposer{}, discardFiles())
	if err == nil {
		t.Fatal("Create with too-long reason = nil, want error")
	}
	var tooLong *backend.ReasonTooLongError
	if !errors.As(err, &tooLong) {
		t.Fatalf("Create = %v, want ReasonTooLongError", err)
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

	created := mustCreateInstance(t, repo, secretId, executor.OperationParameters{Reason: "create", StartedBy: "user"})
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
