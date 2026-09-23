package sqlite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type gateProposer struct {
	ready    chan struct{}
	attempts chan string
	results  chan error
	record   func(by string) error
}

func newGateProposer(record func(by string) error) *gateProposer {
	return &gateProposer{
		ready:    make(chan struct{}),
		attempts: make(chan string),
		results:  make(chan error),
		record:   record,
	}
}

func (g *gateProposer) Propose(ctx context.Context, _ secrets.OperationName, _ executor.OperationParameters) error {
	close(g.ready)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case by := <-g.attempts:
			err := g.record(by)
			g.results <- err
			if err == nil {
				return nil
			}
			if !errors.Is(err, backend.ErrNotApprover) {
				return err
			}
		}
	}
}

func waitReady(t *testing.T, ready <-chan struct{}) {
	t.Helper()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("approval waiter was not entered")
	}
}

func delegatedSecret(script string) *secrets.Secret {
	return &secrets.Secret{
		Id:      "s1",
		Version: 1,
		Create:  command.New(script, command.NewEnvironment(), ""),
		Parents: []string{"linux:agent/1"},
	}
}

func TestGrant_directStartExecutes(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	repo := newTestBackend(t, secrets.Secrets{"s1": delegatedSecret(fmt.Sprintf("printf '' > %q", marker))})
	ctx := context.Background()

	_, handle, err := repo.Runner("s1").Run(ctx, secrets.Create, "", executor.OperationParameters{
		Reason:    "r",
		StartedBy: "linux:john/2",
	}, nil, discardStdio())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if got.Status.AwaitingApproval || got.Status.ApprovedBy != "" || got.Status.CompletedAt == nil {
		t.Fatalf("status = %+v", got.Status)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("command did not run: %v", err)
	}
}

func TestGrant_holdsUntilEligibleApproval(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	secret := delegatedSecret(fmt.Sprintf("printf '' > %q", marker))
	repo := newTestBackend(t, secrets.Secrets{"s1": secret})
	ctx := context.Background()
	var instanceID string
	proposer := newGateProposer(func(by string) error {
		return repo.RecordApproval(context.Background(), instanceID, by)
	})

	started, handle, err := repo.Runner("s1").Run(ctx, secrets.Create, "", executor.OperationParameters{
		Reason:    "r",
		StartedBy: "linux:agent/1",
	}, proposer, discardStdio())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	instanceID = started.Id
	if !started.Status.AwaitingApproval {
		t.Fatal("accepted snapshot should be awaiting approval")
	}
	if !started.Status.ApprovalRequired {
		t.Fatal("accepted snapshot should record that approval is required")
	}
	waitReady(t, proposer.ready)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran before approval")
	}

	proposer.attempts <- "linux:agent/1"
	if err := <-proposer.results; !errors.Is(err, backend.ErrNotApprover) {
		t.Fatalf("starter approval = %v, want ErrNotApprover", err)
	}
	secret.Parents = nil
	proposer.attempts <- "linux:agent/1"
	if err := <-proposer.results; !errors.Is(err, backend.ErrNotApprover) {
		t.Fatalf("starter approval after parent list change = %v, want ErrNotApprover", err)
	}
	proposer.attempts <- "linux:eve/9"
	if err := <-proposer.results; err != nil {
		t.Fatalf("originating principal = %v", err)
	}

	final, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if final.Status.CompletedAt == nil || final.Status.ApprovedBy != "linux:eve/9" || final.Status.AwaitingApproval || !final.Status.ApprovalRequired {
		t.Fatalf("final status = %+v", final.Status)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("command did not run after approval: %v", err)
	}
}

func TestGrant_cancelWhileHeld(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	repo := newTestBackend(t, secrets.Secrets{"s1": delegatedSecret(fmt.Sprintf("printf '' > %q", marker))})
	ctx := context.Background()
	proposer := newGateProposer(func(string) error { return backend.ErrNotApprover })
	_, handle, err := repo.Runner("s1").Run(ctx, secrets.Create, "", executor.OperationParameters{
		Reason:    "r",
		StartedBy: "linux:agent/1",
	}, proposer, discardStdio())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	waitReady(t, proposer.ready)
	if err := handle.Cancel(ctx); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	final, err := handle.Wait(ctx)
	if err == nil {
		t.Fatal("Wait after Cancel = nil, want error")
	}
	if final == nil || final.Status.FailedAt == nil || final.Status.AwaitingApproval || final.Status.ApprovedBy != "" {
		t.Fatalf("final = %+v, want failed and not awaiting", final)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran after cancel")
	}
}

func TestGrant_nilProposerFailsHeld(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	repo := newTestBackend(t, secrets.Secrets{"s1": delegatedSecret(fmt.Sprintf("printf '' > %q", marker))})
	_, handle, err := repo.Runner("s1").Run(context.Background(), secrets.Create, "", executor.OperationParameters{
		Reason:    "r",
		StartedBy: "linux:agent/1",
	}, nil, discardStdio())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	final, err := handle.Wait(context.Background())
	if err == nil {
		t.Fatal("Wait = nil, want error")
	}
	if final == nil || final.Status.FailedAt == nil || final.Status.ApprovedBy != "" {
		t.Fatalf("final = %+v", final)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran without a proposer")
	}
}

func TestGrant_noopProposeDoesNotApprove(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	repo := newTestBackend(t, secrets.Secrets{"s1": delegatedSecret(fmt.Sprintf("printf '' > %q", marker))})
	_, handle, err := repo.Runner("s1").Run(context.Background(), secrets.Create, "", executor.OperationParameters{
		Reason:    "r",
		StartedBy: "linux:agent/1",
	}, noopProposer{}, discardStdio())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	final, err := handle.Wait(context.Background())
	if err == nil {
		t.Fatal("Wait = nil, want error")
	}
	if final == nil || final.Status.FailedAt == nil || final.Status.ApprovedBy != "" {
		t.Fatalf("final = %+v", final)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("command ran after a no-op propose")
	}
}

func TestProposal_visibleOnRunningInstance(t *testing.T) {
	repo := newTestBackend(t, secrets.Secrets{"s1": {
		Id:      "s1",
		Version: 1,
		Create:  command.New("read -r _ || exit 0", command.NewEnvironment(), ""),
	}})
	ctx := context.Background()
	stdinR, stdinW := io.Pipe()
	t.Cleanup(func() { _ = stdinR.Close() })
	t.Cleanup(func() { _ = stdinW.Close() })

	started, handle, err := repo.Runner("s1").Run(ctx, secrets.Create, "", executor.OperationParameters{
		Reason:    "r",
		StartedBy: "linux:john/2",
	}, noopProposer{}, command.Stdio{Stdin: stdinR, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	proposal := &secrets.Proposal{
		SecretID:        "secret-b",
		InstanceID:      "child",
		OperationNumber: 1,
		Name:            secrets.Activate,
		At:              "ssh://b",
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err = repo.SetProposal(ctx, started.Id, proposal)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SetProposal: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if proposal.ID == "" {
		t.Fatal("SetProposal should assign an id")
	}

	got, err := repo.Catalog().Instances().Get(ctx, started.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.Proposal == nil || got.Status.Proposal.ID != proposal.ID || got.Status.Proposal.At != "ssh://b" {
		t.Fatalf("proposal = %+v", got.Status.Proposal)
	}
	if got.Status.CompletedAt != nil {
		t.Fatal("parent completed while proposal was open")
	}

	if err := repo.ClearProposal(ctx, started.Id); err != nil {
		t.Fatalf("ClearProposal: %v", err)
	}
	got, err = repo.Catalog().Instances().Get(ctx, started.Id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status.Proposal != nil {
		t.Fatalf("proposal still set: %+v", got.Status.Proposal)
	}

	_ = stdinW.Close()
	final, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if final.Status.Proposal != nil || final.Status.CompletedAt == nil {
		t.Fatalf("final = %+v", final.Status)
	}

	if err := repo.SetProposal(ctx, started.Id, proposal); err == nil {
		t.Fatal("SetProposal on finished op = nil, want error")
	}
}
