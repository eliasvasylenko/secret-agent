package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"database/sql"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/marshal"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// Repository persists secrets, instances, and operations in sqlite.
type Repository struct {
	db           *sql.DB
	secrets      secrets.Secrets
	maxReasonLen int
	secretStates sync.Map
}

type secretState struct {
	repo         *Repository
	secretId     string
	secret       *secrets.Secret
	maxReasonLen int
}

func NewRepository(ctx context.Context, dbFile string, secrets secrets.Secrets, debug bool, maxReasonLen int) (*Repository, error) {
	dsn := dbFile
	if strings.Contains(dsn, "?") {
		dsn += "&_fk=1"
	} else {
		dsn += "?_fk=1"
	}
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS secret (
			id TEXT NOT NULL PRIMARY KEY,
			activeInstanceId TEXT,
			FOREIGN KEY (activeInstanceId) REFERENCES instance(id) DEFERRABLE INITIALLY DEFERRED
		);
		CREATE TABLE IF NOT EXISTS revision (
			secretId TEXT NOT NULL,
			version INTEGER NOT NULL,
			plan JSONB NOT NULL,
			PRIMARY KEY (secretId, version),
			FOREIGN KEY (secretId) REFERENCES secret(id)
		);
		CREATE TABLE IF NOT EXISTS instance (
			id TEXT NOT NULL PRIMARY KEY,
			secretId TEXT NOT NULL,
			version INTEGER NOT NULL,
			FOREIGN KEY (secretId) REFERENCES secret(id),
			FOREIGN KEY (secretId, version) REFERENCES revision(secretId, version)
		);
		CREATE TABLE IF NOT EXISTS operation (
			id INTEGER NOT NULL PRIMARY KEY,
			secretId TEXT NOT NULL,
			instanceId TEXT NOT NULL,
			name VARCHAR(32) NOT NULL,
			forced INTEGER NOT NULL,
			reason TEXT NOT NULL,
			startedBy TEXT NOT NULL,
			startedAt DATETIME NOT NULL,
			completedAt DATETIME,
			failedAt DATETIME,
			approvalRequired INTEGER NOT NULL DEFAULT 0,
			approvedBy TEXT NOT NULL DEFAULT '',
			proposal TEXT,
			FOREIGN KEY(secretId) REFERENCES secret(id)
			FOREIGN KEY(instanceId) REFERENCES instance(id)
		);
		CREATE INDEX IF NOT EXISTS instance_operation ON operation (instanceId, id DESC);
		CREATE INDEX IF NOT EXISTS secret_operation ON operation (secretId, id DESC);
	`)
	if err != nil {
		db.Close()
		return nil, err
	}
	for _, secret := range secrets {
		if err := secret.ValidateParents(); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := ensureApprovalColumns(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if err := syncPlanRevisions(ctx, db, secrets); err != nil {
		db.Close()
		return nil, err
	}
	return &Repository{
		db:           db,
		secrets:      secrets,
		maxReasonLen: maxReasonLen,
	}, nil
}

func (r *Repository) Close() {
	r.db.Close()
}

func (r *Repository) secretState(secretId string) *secretState {
	if v, ok := r.secretStates.Load(secretId); ok {
		return v.(*secretState)
	}
	state := &secretState{
		repo:         r,
		secretId:     secretId,
		secret:       r.secrets[secretId],
		maxReasonLen: r.maxReasonLen,
	}
	actual, _ := r.secretStates.LoadOrStore(secretId, state)
	return actual.(*secretState)
}

func (r *Repository) listSecrets(ctx context.Context) (secrets.Secrets, error) {
	return r.secrets, nil
}

func (r *Repository) getSecret(ctx context.Context, secretId string) (*secrets.Secret, error) {
	secret, ok := r.secrets[secretId]
	if !ok {
		return nil, fmt.Errorf("Secret plan does not exist %s", secretId)
	}
	return secret, nil
}

func (r *Repository) listInstances(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error) {
	query := `
		SELECT
			i.id,
			r.plan,
			o.id,
			o.name,
			o.forced,
			o.reason,
			o.startedBy,
			o.startedAt,
			o.completedAt,
			o.failedAt,
			o.approvalRequired,
			o.approvedBy,
			o.proposal
		FROM instance i
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
	`
	args := []any{}
	if secretId != nil {
		query += " WHERE i.secretId = ?"
		args = append(args, *secretId)
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, to-from, from)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInstances(rows)
}

func (r *Repository) getInstance(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	instance := &secrets.Instance{Id: instanceId}
	var secretBytes []byte
	var approvalRequired int
	var proposalJSON sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT
			r.plan,
			o.id,
			o.name,
			o.forced,
			o.reason,
			o.startedBy,
			o.startedAt,
			o.completedAt,
			o.failedAt,
			o.approvalRequired,
			o.approvedBy,
			o.proposal
		FROM instance i
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE i.id = ?
	`, instanceId).Scan(
		&secretBytes,
		&instance.Status.OperationNumber,
		&instance.Status.Name,
		&instance.Status.Forced,
		&instance.Status.Reason,
		&instance.Status.StartedBy,
		&instance.Status.StartedAt,
		&instance.Status.CompletedAt,
		&instance.Status.FailedAt,
		&approvalRequired,
		&instance.Status.ApprovedBy,
		&proposalJSON,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(secretBytes, &instance.Secret); err != nil {
		return nil, err
	}
	if err := finishStatus(&instance.Status, approvalRequired != 0, proposalJSON); err != nil {
		return nil, err
	}
	return instance, nil
}

func (r *Repository) getActiveInstance(ctx context.Context, secretId string) (*secrets.Instance, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			i.id,
			r.plan,
			o.id,
			o.name,
			o.forced,
			o.reason,
			o.startedBy,
			o.startedAt,
			o.completedAt,
			o.failedAt,
			o.approvalRequired,
			o.approvedBy,
			o.proposal
		FROM secret s
		INNER JOIN instance i
			ON i.id = s.activeInstanceId
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE s.id = ?
	`, secretId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	instance := &secrets.Instance{}
	var secretBytes []byte
	var approvalRequired int
	var proposalJSON sql.NullString
	err = rows.Scan(
		&instance.Id,
		&secretBytes,
		&instance.Status.OperationNumber,
		&instance.Status.Name,
		&instance.Status.Forced,
		&instance.Status.Reason,
		&instance.Status.StartedBy,
		&instance.Status.StartedAt,
		&instance.Status.CompletedAt,
		&instance.Status.FailedAt,
		&approvalRequired,
		&instance.Status.ApprovedBy,
		&proposalJSON,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(secretBytes, &instance.Secret); err != nil {
		return nil, err
	}
	if err := finishStatus(&instance.Status, approvalRequired != 0, proposalJSON); err != nil {
		return nil, err
	}
	return instance, nil
}

func (r *Repository) listOperations(ctx context.Context, secretId, instanceId *string, from, to int) ([]*secrets.Operation, error) {
	query := `
		SELECT
			id,
			secretId,
			instanceId,
			name,
			forced,
			reason,
			startedBy,
			startedAt,
			completedAt,
			failedAt,
			approvalRequired,
			approvedBy,
			proposal
		FROM operation
		WHERE 1=1
	`
	args := []any{}
	if secretId != nil {
		query += " AND secretId = ?"
		args = append(args, *secretId)
	}
	if instanceId != nil {
		query += " AND instanceId = ?"
		args = append(args, *instanceId)
	}
	query += " LIMIT ? OFFSET ?"
	args = append(args, to-from, from)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOperations(rows)
}

func (st *secretState) beginCreate(ctx context.Context, parameters executor.OperationParameters) (*secrets.Instance, secrets.Operation, error) {
	if err := parameters.Validate(st.maxReasonLen); err != nil {
		return nil, secrets.Operation{}, err
	}
	if st.secret == nil {
		return nil, secrets.Operation{}, fmt.Errorf("Secret plan does not exist %s", st.secretId)
	}

	tx, commit, rollback, err := beginTx(st.repo.db)
	if err != nil {
		return nil, secrets.Operation{}, err
	}
	defer rollback()

	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO secret(id) VALUES (?)`, st.secretId); err != nil {
		return nil, secrets.Operation{}, err
	}

	instanceId := uuid.NewString()
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO instance(id, secretId, version) VALUES(?, ?, ?)
	`, instanceId, st.secretId, st.secret.Version); err != nil {
		return nil, secrets.Operation{}, err
	}

	operation, err := startOperation(ctx, tx, st.secret, instanceId, secrets.Create, parameters)
	if err != nil {
		return nil, secrets.Operation{}, err
	}
	if err = commit(); err != nil {
		return nil, secrets.Operation{}, err
	}

	instance := &secrets.Instance{
		Id:     instanceId,
		Status: operation.Status,
		Secret: *st.secret,
	}
	return instance, operation, nil
}

func (st *secretState) beginUpdate(ctx context.Context, instanceId string, operationName secrets.OperationName, parameters executor.OperationParameters) (*secrets.Instance, secrets.Operation, error) {
	if err := parameters.Validate(st.maxReasonLen); err != nil {
		return nil, secrets.Operation{}, err
	}

	tx, commit, rollback, err := beginTx(st.repo.db)
	if err != nil {
		return nil, secrets.Operation{}, err
	}
	defer rollback()

	var secretBytes []byte
	var activeInstanceId *string
	var previousOperation secrets.Operation
	err = tx.QueryRowContext(ctx, `
		SELECT
			r.plan,
			s.activeInstanceId,
			o.id,
			o.name,
			o.startedAt,
			o.completedAt,
			o.failedAt
		FROM instance i
		INNER JOIN secret s
			ON s.id = i.secretId
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE i.id = ?
	`, instanceId).Scan(
		&secretBytes,
		&activeInstanceId,
		&previousOperation.OperationNumber,
		&previousOperation.Name,
		&previousOperation.StartedAt,
		&previousOperation.CompletedAt,
		&previousOperation.FailedAt,
	)
	if err != nil {
		return nil, secrets.Operation{}, err
	}

	var secretPlan secrets.Secret
	if err = json.Unmarshal(secretBytes, &secretPlan); err != nil {
		return nil, secrets.Operation{}, err
	}

	var msg string
	if parameters.ExpectedOperationNumber != nil && previousOperation.OperationNumber != *parameters.ExpectedOperationNumber {
		msg = fmt.Sprintf("%s when previous operation %d does not match expected %d", operationName, previousOperation.OperationNumber, *parameters.ExpectedOperationNumber)
	} else if previousOperation.CompletedAt == nil && operationName != previousOperation.Name {
		msg = fmt.Sprintf("%s when previous %s has not succeeded", operationName, previousOperation.Name)
	} else if operationName == secrets.Activate && activeInstanceId != nil {
		msg = fmt.Sprintf("%s when instance %s is active", operationName, *activeInstanceId)
	} else if (operationName == secrets.Test || operationName == secrets.Deactivate) && (activeInstanceId == nil || *activeInstanceId != instanceId) {
		msg = fmt.Sprintf("%s when instance is not active", operationName)
	}

	if msg != "" {
		if parameters.Forced {
			log.Default().Printf("forcing %s", msg)
		} else {
			return nil, secrets.Operation{}, fmt.Errorf("cannot %s", msg)
		}
	}

	operation, err := startOperation(ctx, tx, st.secret, instanceId, operationName, parameters)
	if err != nil {
		return nil, secrets.Operation{}, err
	}
	if err = commit(); err != nil {
		return nil, secrets.Operation{}, err
	}

	instance := &secrets.Instance{
		Id:     instanceId,
		Status: operation.Status,
		Secret: secretPlan,
	}
	return instance, operation, nil
}

func (st *secretState) launch(instance *secrets.Instance, operation secrets.Operation, parameters executor.OperationParameters, proposer backend.Proposer, stdio command.Stdio) *opHandle {
	execCtx, execCancel := context.WithCancel(context.Background())
	h := &opHandle{
		done:       make(chan struct{}),
		execCancel: execCancel,
	}

	repo := st.repo
	secretId := st.secretId
	inst := instance
	go func() {
		defer close(h.done)
		if operation.ApprovalRequired {
			err := approveHeld(execCtx, repo, inst.Id, operation, parameters, proposer)
			if err != nil {
				_ = repo.failOperation(context.Background(), operation.OperationNumber)
				h.waitErr = err
				got, getErr := repo.getInstance(context.Background(), inst.Id)
				if getErr != nil {
					h.waitErr = getErr
					return
				}
				h.final = got
				return
			}
		}
		err := completeOperation(execCtx, repo.db, secretId, inst, operation, parameters, stdio)
		got, getErr := repo.getInstance(context.Background(), inst.Id)
		if getErr != nil {
			h.waitErr = getErr
			return
		}
		h.final = got
		if err != nil {
			h.waitErr = err
		}
	}()

	return h
}

type opHandle struct {
	done       chan struct{}
	execCancel context.CancelFunc
	final      *secrets.Instance
	waitErr    error
}

func beginTx(db *sql.DB) (*sql.Tx, func() error, func(), error) {
	tx, err := db.Begin()
	committed := false
	commit := func() error {
		committed = true
		return tx.Commit()
	}
	rollback := func() {
		if committed {
			return
		}
		committed = true
		if err := tx.Rollback(); err != nil {
			log.Default().Printf("rollback error %s", err.Error())
		}
	}
	return tx, commit, rollback, err
}

func startOperation(ctx context.Context, tx *sql.Tx, secret *secrets.Secret, instanceId string, operationName secrets.OperationName, parameters executor.OperationParameters) (secrets.Operation, error) {
	if secret == nil {
		return secrets.Operation{}, fmt.Errorf("secret plan does not exist")
	}
	approvalRequired := secret.Parent(parameters.StartedBy)
	operation := secrets.Operation{
		SecretId:   secret.Id,
		InstanceId: instanceId,
		Status: secrets.Status{
			Name:             operationName,
			Forced:           parameters.Forced,
			Reason:           parameters.Reason,
			StartedBy:        parameters.StartedBy,
			ApprovalRequired: approvalRequired,
			AwaitingApproval: approvalRequired,
		},
	}
	err := tx.QueryRowContext(ctx, `
		INSERT INTO operation (secretId, instanceId, name, forced, reason, startedBy, startedAt, approvalRequired)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			RETURNING id, startedAt
	`, secret.Id, instanceId, operation.Name, operation.Forced, operation.Reason, operation.StartedBy, time.Now(), approvalRequired).Scan(&operation.OperationNumber, &operation.StartedAt)
	return operation, err
}

func completeOperation(ctx context.Context, db *sql.DB, secretId string, instance *secrets.Instance, operation secrets.Operation, parameters executor.OperationParameters, stdio command.Stdio) error {
	processErr := executor.Execute(ctx, &instance.Secret, operation.Name, stdio, parameters, operation.InstanceId)

	// Persist terminal state with a fresh ctx: execute ctx may already be canceled (Handle.Cancel).
	dbCtx := context.Background()

	tx, commit, rollback, err := beginTx(db)
	if err != nil {
		return err
	}
	defer rollback()

	if operation.Name == secrets.Activate {
		tx.ExecContext(dbCtx, `UPDATE secret SET activeInstanceId = ? WHERE id = ?`, instance.Id, secretId)
	}

	if processErr != nil {
		if err := tx.QueryRowContext(dbCtx, `
			UPDATE operation SET failedAt = ?, proposal = NULL WHERE id = ? RETURNING failedAt
		`, time.Now(), operation.OperationNumber).Scan(&instance.Status.FailedAt); err != nil {
			return err
		}
		if err := commit(); err != nil {
			return err
		}
		return processErr
	}

	if operation.Name == secrets.Deactivate {
		tx.ExecContext(dbCtx, `UPDATE secret SET activeInstanceId = NULL WHERE id = ?`, secretId)
	}
	if err := tx.QueryRowContext(dbCtx, `
		UPDATE operation SET completedAt = ?, proposal = NULL WHERE id = ? RETURNING completedAt
	`, time.Now(), operation.OperationNumber).Scan(&instance.Status.CompletedAt); err != nil {
		return err
	}
	return commit()
}

func scanInstances(rows *sql.Rows) (secrets.Instances, error) {
	instances := secrets.Instances{}
	for rows.Next() {
		instance := &secrets.Instance{}
		var secretBytes []byte
		var approvalRequired int
		var proposalJSON sql.NullString
		if err := rows.Scan(
			&instance.Id,
			&secretBytes,
			&instance.Status.OperationNumber,
			&instance.Status.Name,
			&instance.Status.Forced,
			&instance.Status.Reason,
			&instance.Status.StartedBy,
			&instance.Status.StartedAt,
			&instance.Status.CompletedAt,
			&instance.Status.FailedAt,
			&approvalRequired,
			&instance.Status.ApprovedBy,
			&proposalJSON,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(secretBytes, &instance.Secret); err != nil {
			return nil, err
		}
		if err := finishStatus(&instance.Status, approvalRequired != 0, proposalJSON); err != nil {
			return nil, err
		}
		instances[instance.Id] = instance
	}
	return instances, rows.Err()
}

func scanOperations(rows *sql.Rows) ([]*secrets.Operation, error) {
	operations := []*secrets.Operation{}
	for rows.Next() {
		operation := &secrets.Operation{}
		var approvalRequired int
		var proposalJSON sql.NullString
		if err := rows.Scan(
			&operation.OperationNumber,
			&operation.SecretId,
			&operation.InstanceId,
			&operation.Name,
			&operation.Forced,
			&operation.Reason,
			&operation.StartedBy,
			&operation.StartedAt,
			&operation.CompletedAt,
			&operation.FailedAt,
			&approvalRequired,
			&operation.ApprovedBy,
			&proposalJSON,
		); err != nil {
			return nil, err
		}
		if err := finishStatus(&operation.Status, approvalRequired != 0, proposalJSON); err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	return operations, rows.Err()
}

func syncPlanRevisions(ctx context.Context, db *sql.DB, secrets secrets.Secrets) error {
	for id, secret := range secrets {
		if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO secret(id) VALUES (?)`, id); err != nil {
			return err
		}
		secretBytes, err := marshal.JSON(secret)
		if err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, `
			INSERT INTO revision (secretId, version, plan)
			VALUES (?, ?, ?)
			ON CONFLICT(secretId, version) DO UPDATE SET plan = excluded.plan
		`, id, secret.Version, secretBytes)
		if err != nil {
			return fmt.Errorf("sync secret %q version %d: %w", id, secret.Version, err)
		}
	}
	return nil
}
