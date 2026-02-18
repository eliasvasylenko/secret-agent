package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/go-cmp/cmp"
)

// noOpSecret has no commands so Process is a no-op (used for store operations that run Process).
var noOpSecret = &secrets.Secret{Name: "s1"}

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
	want := secrets.Secrets{"s1": noOpSecret, "s2": {Name: "s2"}}
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
		wantName string
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
			if got.Name != tt.wantName {
				t.Errorf("Get().Name = %q, want %q", got.Name, tt.wantName)
			}
		})
	}
}

func TestSecretRepository_Instances_Create_unknownSecret(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("nonexistent")

	_, err := instances.Create(ctx, secrets.OperationParameters{Reason: "r", StartedBy: "u"})
	if err == nil {
		t.Fatal("Create = nil, want error")
	}
}

func TestInstanceRepository_Create_List_Get(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	created, err := instances.Create(ctx, secrets.OperationParameters{Reason: "create", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Id == "" {
		t.Error("Create returned instance with empty Id")
	}
	if created.Secret.Name != "s1" {
		t.Errorf("Create returned Secret.Name = %q", created.Secret.Name)
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

	// No active instance initially
	active, err := instances.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive (no active): %v", err)
	}
	if active != nil {
		t.Errorf("GetActive = %v, want nil", active)
	}

	created, err := instances.Create(ctx, secrets.OperationParameters{Reason: "create", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = instances.Activate(ctx, created.Id, secrets.OperationParameters{Reason: "activate", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}

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

	created, err := instances.Create(ctx, secrets.OperationParameters{Reason: "create", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	ops, err := instances.History(ctx, created.Id, 0, 10)
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

	created, err := instances.Create(ctx, secrets.OperationParameters{Reason: "create", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Status.Name != secrets.Create {
		t.Errorf("Create returned instance with status %s, want %s", created.Status.Name, secrets.Create)
	}

	activated, err := instances.Activate(ctx, created.Id, secrets.OperationParameters{Reason: "activate", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	active, _ := instances.GetActive(ctx)
	if active == nil || active.Id != created.Id {
		t.Errorf("after Activate, GetActive = %v", active)
	}
	if activated.Status.Name != secrets.Activate {
		t.Errorf("Activate returned instance with status %s, want %s", activated.Status.Name, secrets.Activate)
	}

	deactivated, err := instances.Deactivate(ctx, created.Id, secrets.OperationParameters{Reason: "deactivate", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	active, _ = instances.GetActive(ctx)
	if active != nil {
		t.Errorf("after Deactivate, GetActive = %v, want nil", active)
	}
	if deactivated.Status.Name != secrets.Deactivate {
		t.Errorf("Deactivate returned instance with status %s, want %s", deactivated.Status.Name, secrets.Deactivate)
	}
}

func TestInstanceRepository_Create_validateReason(t *testing.T) {
	repo := newTestRepo(t, nil)
	ctx := context.Background()
	instances := repo.Instances("s1")

	_, err := instances.Create(ctx, secrets.OperationParameters{Reason: "ok", StartedBy: "user"})
	if err != nil {
		t.Fatalf("Create (short reason): %v", err)
	}

	// maxReasonLen is 256 in newTestRepo
	longReason := string(make([]byte, 257))
	_, err = instances.Create(ctx, secrets.OperationParameters{Reason: longReason, StartedBy: "user"})
	if err == nil {
		t.Fatal("Create with too-long reason = nil, want error")
	}
}
