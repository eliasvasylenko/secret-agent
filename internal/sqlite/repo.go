package sqlite

import (
	"context"
	"encoding/json"
	"errors"
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

// Repository persists secrets and the current status of their instances.
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
			revision INTEGER NOT NULL,
			state VARCHAR(32) NOT NULL,
			stateEnteredAt DATETIME,
			opName VARCHAR(32) NOT NULL,
			opForced INTEGER NOT NULL,
			opReason TEXT NOT NULL,
			opCreatedBy TEXT NOT NULL,
			opCreatedAt DATETIME NOT NULL,
			opStartedBy TEXT NOT NULL,
			opStartedAt DATETIME NOT NULL,
			opCompletedAt DATETIME,
			opFailedAt DATETIME,
			FOREIGN KEY (secretId) REFERENCES secret(id),
			FOREIGN KEY (secretId, version) REFERENCES revision(secretId, version)
		);
	`)
	if err != nil {
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

func (r *Repository) listSecrets(_ context.Context) (secrets.Secrets, error) {
	return r.secrets, nil
}

func (r *Repository) getSecret(_ context.Context, secretId string) (*secrets.Secret, error) {
	secret, ok := r.secrets[secretId]
	if !ok {
		return nil, fmt.Errorf("Secret plan does not exist %s", secretId)
	}
	return secret, nil
}

const instanceSnapshotColumns = `
	i.id,
	i.secretId,
	r.plan,
	i.revision,
	i.state,
	i.stateEnteredAt,
	i.opName,
	i.opForced,
	i.opReason,
	i.opCreatedBy,
	i.opCreatedAt,
	i.opStartedBy,
	i.opStartedAt,
	i.opCompletedAt,
	i.opFailedAt`

func (r *Repository) listInstances(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error) {
	query := `
		SELECT` + instanceSnapshotColumns + `
		FROM instance i
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
	`
	args := []any{}
	if secretId != nil {
		query += " WHERE i.secretId = ?"
		args = append(args, *secretId)
	}
	// Page in the same order MarshalJSON emits: newest createdAt, then id.
	query += " ORDER BY i.opCreatedAt DESC, i.id ASC LIMIT ? OFFSET ?"
	args = append(args, to-from, from)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanInstances(rows)
}

func (r *Repository) getInstance(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT`+instanceSnapshotColumns+`
		FROM instance i
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		WHERE i.id = ?
	`, instanceId)
	instance, err := scanInstance(row)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (r *Repository) getActiveInstance(ctx context.Context, secretId string) (*secrets.Instance, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT`+instanceSnapshotColumns+`
		FROM secret s
		INNER JOIN instance i
			ON i.id = s.activeInstanceId
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		WHERE s.id = ?
	`, secretId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	instance, err := scanInstance(rows)
	if err != nil {
		return nil, err
	}
	return instance, nil
}

func (st *secretState) startCreateOperation(ctx context.Context, parameters executor.OperationParameters) (*secrets.Instance, secrets.Operation, error) {
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
	operation, revision, err := createInstance(ctx, tx, st.secretId, instanceId, st.secret.Version, parameters)
	if err != nil {
		return nil, secrets.Operation{}, err
	}
	if err = commit(); err != nil {
		return nil, secrets.Operation{}, err
	}

	instance := &secrets.Instance{
		Id:        instanceId,
		Revision:  revision,
		State:     secrets.State{Name: secrets.Proposed, EnteredAt: *operation.StartedAt},
		Operation: operation,
		Secret:    *st.secret,
	}
	return instance, operation, nil
}

func (st *secretState) startUpdateOperation(ctx context.Context, instanceId string, operationName secrets.OperationName, parameters executor.OperationParameters) (*secrets.Instance, secrets.Operation, error) {
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
	var revision int
	var stateName string
	var stateEnteredAt sql.NullTime
	var previousName string
	var previousCompletedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT
			r.plan,
			s.activeInstanceId,
			i.revision,
			i.state,
			i.stateEnteredAt,
			i.opName,
			i.opCompletedAt
		FROM instance i
		INNER JOIN secret s
			ON s.id = i.secretId
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		WHERE i.id = ?
	`, instanceId).Scan(
		&secretBytes,
		&activeInstanceId,
		&revision,
		&stateName,
		&stateEnteredAt,
		&previousName,
		&previousCompletedAt,
	)
	if err != nil {
		return nil, secrets.Operation{}, err
	}

	var secretPlan secrets.Secret
	if err = json.Unmarshal(secretBytes, &secretPlan); err != nil {
		return nil, secrets.Operation{}, err
	}

	var msg string
	if parameters.ExpectedRevision != nil && revision != *parameters.ExpectedRevision {
		msg = fmt.Sprintf("%s when revision %d does not match expected %d", operationName, revision, *parameters.ExpectedRevision)
	} else if !previousCompletedAt.Valid && operationName != secrets.OperationName(previousName) {
		msg = fmt.Sprintf("%s when previous %s has not succeeded", operationName, previousName)
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

	operation, revision, err := updateInstance(ctx, tx, st.secretId, instanceId, operationName, parameters)
	if err != nil {
		return nil, secrets.Operation{}, err
	}
	if err = commit(); err != nil {
		return nil, secrets.Operation{}, err
	}

	instance := &secrets.Instance{
		Id:        instanceId,
		Revision:  revision,
		State:     secrets.State{Name: secrets.StateName(stateName)},
		Operation: operation,
		Secret:    secretPlan,
	}
	if stateEnteredAt.Valid {
		instance.State.EnteredAt = stateEnteredAt.Time
	}
	return instance, operation, nil
}

func (st *secretState) launch(instance *secrets.Instance, operation secrets.Operation, parameters executor.OperationParameters, proposer backend.Proposer, stdio command.Files) *opHandle {
	execCtx, execCancel := context.WithCancel(context.Background())
	h := &opHandle{
		done:       make(chan struct{}),
		execCancel: execCancel,
		proposer:   proposer,
	}

	repo := st.repo
	secretId := st.secretId
	inst := instance
	go func() {
		defer close(h.done)
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
	proposer   backend.Proposer
	final      *secrets.Instance
	waitErr    error
}

func beginTx(db *sql.DB) (*sql.Tx, func() error, func(), error) {
	tx, err := db.Begin()
	committed := false
	commit := func() error {
		err := tx.Commit()
		if err != nil {
			return err
		}
		committed = true
		return nil
	}
	rollback := func() {
		if committed {
			return
		}
		committed = true
		// Commit may already have finished the transaction. Rollback then
		// returns ErrTxDone, which is not a failure to undo the work.
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Default().Printf("rollback error %s", err.Error())
		}
	}
	return tx, commit, rollback, err
}

func newOperation(secretId, instanceId string, name secrets.OperationName, parameters executor.OperationParameters, now time.Time) secrets.Operation {
	createdBy := parameters.CreatedBy
	if createdBy == "" {
		createdBy = parameters.StartedBy
	}
	createdAt := parameters.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	startedAt := now
	return secrets.Operation{
		SecretId:   secretId,
		InstanceId: instanceId,
		Name:       name,
		Forced:     parameters.Forced,
		Reason:     parameters.Reason,
		CreatedBy:  createdBy,
		CreatedAt:  createdAt,
		StartedBy:  parameters.StartedBy,
		StartedAt:  &startedAt,
	}
}

func createInstance(ctx context.Context, tx *sql.Tx, secretId, instanceId string, version int, parameters executor.OperationParameters) (secrets.Operation, int, error) {
	operation := newOperation(secretId, instanceId, secrets.Create, parameters, time.Now())
	var revision int
	var startedAt time.Time
	err := tx.QueryRowContext(ctx, `
		INSERT INTO instance (
			id, secretId, version, revision, state, stateEnteredAt,
			opName, opForced, opReason, opCreatedBy, opCreatedAt, opStartedBy, opStartedAt
		) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING revision, opStartedAt
	`, instanceId, secretId, version, secrets.Proposed, *operation.StartedAt,
		operation.Name, operation.Forced, operation.Reason, operation.CreatedBy, operation.CreatedAt, operation.StartedBy, *operation.StartedAt,
	).Scan(&revision, &startedAt)
	operation.StartedAt = &startedAt
	return operation, revision, err
}

func updateInstance(ctx context.Context, tx *sql.Tx, secretId, instanceId string, operationName secrets.OperationName, parameters executor.OperationParameters) (secrets.Operation, int, error) {
	operation := newOperation(secretId, instanceId, operationName, parameters, time.Now())
	var revision int
	var startedAt time.Time
	err := tx.QueryRowContext(ctx, `
		UPDATE instance SET
			revision = revision + 1,
			opName = ?,
			opForced = ?,
			opReason = ?,
			opCreatedBy = ?,
			opCreatedAt = ?,
			opStartedBy = ?,
			opStartedAt = ?,
			opCompletedAt = NULL,
			opFailedAt = NULL
		WHERE id = ?
		RETURNING revision, opStartedAt
	`, operation.Name, operation.Forced, operation.Reason, operation.CreatedBy, operation.CreatedAt, operation.StartedBy, *operation.StartedAt, instanceId).Scan(&revision, &startedAt)
	operation.StartedAt = &startedAt
	return operation, revision, err
}

func completeOperation(ctx context.Context, db *sql.DB, secretId string, instance *secrets.Instance, operation secrets.Operation, parameters executor.OperationParameters, stdio command.Files) error {
	processErr := executor.Execute(ctx, &instance.Secret, operation.Name, stdio, parameters, operation.InstanceId)

	// Persist terminal state with a fresh ctx: execute ctx may already be canceled (Handle.Cancel).
	dbCtx := context.Background()

	tx, commit, rollback, err := beginTx(db)
	if err != nil {
		return err
	}
	defer rollback()

	now := time.Now()
	if processErr != nil {
		if _, err := tx.ExecContext(dbCtx, `
			UPDATE instance SET revision = revision + 1, opFailedAt = ? WHERE id = ?
		`, now, instance.Id); err != nil {
			return err
		}
		if err := commit(); err != nil {
			return err
		}
		return processErr
	}

	if operation.Name == secrets.Activate {
		if _, err := tx.ExecContext(dbCtx, `UPDATE secret SET activeInstanceId = ? WHERE id = ?`, instance.Id, secretId); err != nil {
			return err
		}
	}
	if operation.Name == secrets.Deactivate {
		if _, err := tx.ExecContext(dbCtx, `UPDATE secret SET activeInstanceId = NULL WHERE id = ?`, secretId); err != nil {
			return err
		}
	}
	target, ok := secrets.TargetState(operation.Name)
	if !ok {
		return fmt.Errorf("operation %s has no target state", operation.Name)
	}
	if _, err := tx.ExecContext(dbCtx, `
		UPDATE instance SET revision = revision + 1, state = ?, stateEnteredAt = ?, opCompletedAt = ? WHERE id = ?
	`, target, now, now, instance.Id); err != nil {
		return err
	}
	return commit()
}

func scanInstances(rows *sql.Rows) (secrets.Instances, error) {
	instances := secrets.Instances{}
	for rows.Next() {
		instance, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		instances[instance.Id] = instance
	}
	return instances, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanInstance(row scanner) (*secrets.Instance, error) {
	instance := &secrets.Instance{}
	var secretBytes []byte
	var stateName string
	var stateEnteredAt, startedAt, completedAt, failedAt sql.NullTime
	var forced int
	if err := row.Scan(
		&instance.Id,
		&instance.Operation.SecretId,
		&secretBytes,
		&instance.Revision,
		&stateName,
		&stateEnteredAt,
		&instance.Operation.Name,
		&forced,
		&instance.Operation.Reason,
		&instance.Operation.CreatedBy,
		&instance.Operation.CreatedAt,
		&instance.Operation.StartedBy,
		&startedAt,
		&completedAt,
		&failedAt,
	); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(secretBytes, &instance.Secret); err != nil {
		return nil, err
	}
	instance.Operation.Forced = forced != 0
	instance.Operation.InstanceId = instance.Id
	instance.Operation.StartedAt = nullTimePtr(startedAt)
	instance.Operation.CompletedAt = nullTimePtr(completedAt)
	instance.Operation.FailedAt = nullTimePtr(failedAt)
	if stateName != "" {
		instance.State = secrets.State{Name: secrets.StateName(stateName)}
		if stateEnteredAt.Valid {
			instance.State.EnteredAt = stateEnteredAt.Time
		}
	}
	return instance, nil
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time
	return &t
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
