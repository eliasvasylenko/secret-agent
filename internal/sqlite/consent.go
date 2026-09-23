package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/uuid"
)

func ensureApprovalColumns(ctx context.Context, db *sql.DB) error {
	have, err := tableColumns(ctx, db, "operation")
	if err != nil {
		return err
	}
	adds := []struct{ name, decl string }{
		{"approvalRequired", "INTEGER NOT NULL DEFAULT 0"},
		{"approvedBy", "TEXT NOT NULL DEFAULT ''"},
		{"proposal", "TEXT"},
	}
	for _, col := range adds {
		if have[col.name] {
			continue
		}
		if _, err := db.ExecContext(ctx, "ALTER TABLE operation ADD COLUMN "+col.name+" "+col.decl); err != nil {
			return err
		}
	}
	return nil
}

func tableColumns(ctx context.Context, db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		have[name] = true
	}
	return have, rows.Err()
}

func decodeProposal(status *secrets.Status, raw sql.NullString) error {
	if !raw.Valid || raw.String == "" {
		return nil
	}
	var proposal secrets.Proposal
	if err := json.Unmarshal([]byte(raw.String), &proposal); err != nil {
		return err
	}
	status.Proposal = &proposal
	return nil
}

func finishStatus(status *secrets.Status, approvalRequired bool, proposalJSON sql.NullString) error {
	status.ApprovalRequired = approvalRequired
	status.AwaitingApproval = approvalRequired && status.ApprovedBy == "" && status.CompletedAt == nil && status.FailedAt == nil
	return decodeProposal(status, proposalJSON)
}

func approveHeld(ctx context.Context, repo *Repository, instanceID string, operation secrets.Operation, parameters executor.OperationParameters, proposer backend.Proposer) error {
	if proposer == nil {
		return fmt.Errorf("held operation has no proposer")
	}
	if err := proposer.Propose(ctx, operation.Name, parameters); err != nil {
		return err
	}
	got, err := repo.getInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	if got.Status.ApprovedBy == "" || got.Status.ApprovedBy == operation.StartedBy {
		return fmt.Errorf("propose returned without an originating principal")
	}
	return nil
}

func (r *Repository) recordInstanceApproval(ctx context.Context, instanceID, by string) error {
	var operationNumber int
	err := r.db.QueryRowContext(ctx, `
		SELECT id FROM operation
		WHERE instanceId = ? AND completedAt IS NULL AND failedAt IS NULL
		ORDER BY id DESC LIMIT 1
	`, instanceID).Scan(&operationNumber)
	if err != nil {
		return err
	}
	return r.recordApproval(ctx, operationNumber, by)
}

func (r *Repository) recordApproval(ctx context.Context, operationNumber int, by string) error {
	if by == "" {
		return backend.ErrNotApprover
	}
	tx, commit, rollback, err := beginTx(r.db)
	if err != nil {
		return err
	}
	defer rollback()

	var approvalRequired int
	var startedBy, approvedBy string
	var completedAt, failedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT approvalRequired, startedBy, approvedBy, completedAt, failedAt
		FROM operation WHERE id = ?
	`, operationNumber).Scan(&approvalRequired, &startedBy, &approvedBy, &completedAt, &failedAt)
	if err != nil {
		return err
	}
	if approvalRequired == 0 || completedAt.Valid || failedAt.Valid || approvedBy != "" {
		return fmt.Errorf("operation %d is not awaiting approval", operationNumber)
	}
	if by == startedBy {
		return backend.ErrNotApprover
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE operation SET approvedBy = ?
		WHERE id = ? AND approvedBy = '' AND completedAt IS NULL AND failedAt IS NULL
	`, by, operationNumber)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated != 1 {
		return fmt.Errorf("operation %d is not awaiting approval", operationNumber)
	}
	return commit()
}

func (r *Repository) failOperation(ctx context.Context, operationNumber int) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE operation
		SET failedAt = ?, proposal = NULL
		WHERE id = ? AND completedAt IS NULL AND failedAt IS NULL
	`, time.Now(), operationNumber)
	return err
}

func (r *Repository) setProposal(ctx context.Context, instanceID string, proposal *secrets.Proposal) error {
	if proposal == nil {
		return fmt.Errorf("proposal required")
	}
	if proposal.ID == "" {
		proposal.ID = uuid.NewString()
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return err
	}
	result, err := r.db.ExecContext(ctx, `
		UPDATE operation SET proposal = ?
		WHERE id = (
			SELECT MAX(id) FROM operation
			WHERE instanceId = ? AND completedAt IS NULL AND failedAt IS NULL
		)
	`, string(raw), instanceID)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return fmt.Errorf("no running operation for instance %s", instanceID)
	}
	return nil
}

func (r *Repository) clearProposal(ctx context.Context, instanceID string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE operation SET proposal = NULL
		WHERE id = (
			SELECT MAX(id) FROM operation
			WHERE instanceId = ? AND completedAt IS NULL AND failedAt IS NULL
		)
	`, instanceID)
	if err != nil {
		return err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if updated == 0 {
		return fmt.Errorf("no running operation for instance %s", instanceID)
	}
	return nil
}
