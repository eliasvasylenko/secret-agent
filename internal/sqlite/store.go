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

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/marshal"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

type operationKey struct {
	instanceId      string
	operationNumber int
}

type operationRuntime struct {
	done   chan struct{}
	cancel context.CancelFunc
}

// An instance store implementation backed by sqlite
type SecretRespository struct {
	db            *sql.DB
	secrets       secrets.Secrets
	maxReasonLen  int
	instanceRepos sync.Map
}

type InstanceRepository struct {
	db           *sql.DB
	secretId     string
	secret       *secrets.Secret
	maxReasonLen int

	mu         sync.Mutex
	operations map[operationKey]*operationRuntime
}

func NewSecretRepository(ctx context.Context, dbFile string, secrets secrets.Secrets, debug bool, maxReasonLen int) (*SecretRespository, error) {
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
	if err := syncPlanRevisions(ctx, db, secrets); err != nil {
		db.Close()
		return nil, err
	}
	return &SecretRespository{
		db:           db,
		secrets:      secrets,
		maxReasonLen: maxReasonLen,
	}, nil
}

func (s *SecretRespository) Close() {
	s.db.Close()
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
		err := tx.Rollback()
		if err != nil {
			log.Default().Printf("rollback error %s", err.Error())
		}
	}
	return tx, commit, rollback, err
}

func (s *SecretRespository) List(ctx context.Context) (secrets.Secrets, error) {
	return s.secrets, nil
}

func (s *SecretRespository) Get(ctx context.Context, secretId string) (*secrets.Secret, error) {
	secret, ok := s.secrets[secretId]
	if !ok {
		return nil, fmt.Errorf("Secret plan does not exist %s", secretId)
	}
	return secret, nil
}

func (s *SecretRespository) History(ctx context.Context, secretId string, startAt int, endAt int) ([]*secrets.Operation, error) {
	rows, err := s.db.QueryContext(ctx, `
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
			failedAt
		FROM operation
		WHERE secretId = ?
		LIMIT ? OFFSET ?
	`, secretId, endAt-startAt, startAt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	operations := []*secrets.Operation{}
	for err == nil && rows.Next() {
		operation := &secrets.Operation{}
		operations = append(operations, operation)
		err = rows.Scan(&operation.OperationNumber, &operation.SecretId, &operation.InstanceId, &operation.Name, &operation.Forced, &operation.Reason, &operation.StartedBy, &operation.StartedAt, &operation.CompletedAt, &operation.FailedAt)
	}
	return operations, err
}

func (s *SecretRespository) Instances(secretId string) *InstanceRepository {
	if v, ok := s.instanceRepos.Load(secretId); ok {
		return v.(*InstanceRepository)
	}
	secret := s.secrets[secretId]
	repo := &InstanceRepository{
		db:           s.db,
		secretId:     secretId,
		secret:       secret,
		maxReasonLen: s.maxReasonLen,
		operations:   make(map[operationKey]*operationRuntime),
	}
	actual, _ := s.instanceRepos.LoadOrStore(secretId, repo)
	return actual.(*InstanceRepository)
}

func (i *InstanceRepository) List(ctx context.Context, from int, to int) (secrets.Instances, error) {
	rows, err := i.db.QueryContext(ctx, `
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
			o.failedAt
		FROM instance i
		INNER JOIN revision r
			ON r.secretId = i.secretId AND r.version = i.version
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE i.secretId = ?
	`, i.secretId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	instances := secrets.Instances{}
	for err == nil && rows.Next() {
		instance := &secrets.Instance{}
		var secretBytes []byte
		err = rows.Scan(&instance.Id, &secretBytes, &instance.Status.OperationNumber, &instance.Status.Name, &instance.Status.Forced, &instance.Status.Reason, &instance.Status.StartedBy, &instance.Status.StartedAt, &instance.Status.CompletedAt, &instance.Status.FailedAt)
		if err != nil {
			break
		}
		instances[instance.Id] = instance
		err = json.Unmarshal(secretBytes, &instance.Secret)
	}
	return instances, err
}

func (i *InstanceRepository) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	instance := &secrets.Instance{
		Id: instanceId,
	}
	var secretBytes []byte
	err := i.db.QueryRowContext(ctx, `
		SELECT
			r.plan,
			o.id,
			o.name,
			o.forced,
			o.reason,
			o.startedBy,
			o.startedAt,
			o.completedAt,
			o.failedAt
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
	`, instanceId).Scan(&secretBytes, &instance.Status.OperationNumber, &instance.Status.Name, &instance.Status.Forced, &instance.Status.Reason, &instance.Status.StartedBy, &instance.Status.StartedAt, &instance.Status.CompletedAt, &instance.Status.FailedAt)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(secretBytes, &instance.Secret)
	return instance, err
}

func (i *InstanceRepository) GetActive(ctx context.Context) (*secrets.Instance, error) {
	rows, err := i.db.QueryContext(ctx, `
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
			o.failedAt
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
	`, i.secretId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}

	var secretBytes []byte
	var instance = &secrets.Instance{}
	err = rows.Scan(&instance.Id, &secretBytes, &instance.Status.OperationNumber, &instance.Status.Name, &instance.Status.Forced, &instance.Status.Reason, &instance.Status.StartedBy, &instance.Status.StartedAt, &instance.Status.CompletedAt, &instance.Status.FailedAt)
	if err != nil {
		return nil, err
	}
	return instance, json.Unmarshal(secretBytes, &instance.Secret)
}

func (i *InstanceRepository) Create(ctx context.Context, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	if err := parameters.Validate(i.maxReasonLen); err != nil {
		return nil, err
	}

	if i.secret == nil {
		return nil, fmt.Errorf("Secret plan does not exist %s", i.secretId)
	}

	tx, commit, rollback, err := beginTx(i.db)
	if err != nil {
		return nil, err
	}
	defer rollback()

	_, err = tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO secret(id)
				VALUES (?)
		`, i.secretId)
	if err != nil {
		return nil, err
	}

	instanceId := uuid.NewString()
	_, err = tx.ExecContext(ctx, `
			INSERT INTO instance(id, secretId, version)
				VALUES(?, ?, ?)
		`, instanceId, i.secretId, i.secret.Version)
	if err != nil {
		return nil, err
	}

	operation, err := startOperation(ctx, tx, i.secretId, instanceId, secrets.Create, parameters)
	if err != nil {
		return nil, err
	}
	err = commit()
	if err != nil {
		return nil, err
	}

	instance := &secrets.Instance{
		Id:     instanceId,
		Status: operation.Status,
		Secret: *i.secret,
	}

	i.launchAsync(instance, operation, parameters, stdio)
	return instance, nil
}

func (i *InstanceRepository) Destroy(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return i.startUpdateOperation(ctx, instanceId, secrets.Destroy, parameters, stdio)
}

func (i *InstanceRepository) Activate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return i.startUpdateOperation(ctx, instanceId, secrets.Activate, parameters, stdio)
}

func (i *InstanceRepository) Deactivate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return i.startUpdateOperation(ctx, instanceId, secrets.Deactivate, parameters, stdio)
}

func (i *InstanceRepository) Test(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return i.startUpdateOperation(ctx, instanceId, secrets.Test, parameters, stdio)
}

func (i *InstanceRepository) startUpdateOperation(ctx context.Context, instanceId string, operationName secrets.OperationName, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	if err := parameters.Validate(i.maxReasonLen); err != nil {
		return nil, err
	}

	tx, commit, rollback, err := beginTx(i.db)
	if err != nil {
		return nil, err
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
	`, instanceId).Scan(&secretBytes, &activeInstanceId, &previousOperation.OperationNumber, &previousOperation.Name, &previousOperation.StartedAt, &previousOperation.CompletedAt, &previousOperation.FailedAt)
	if err != nil {
		return nil, err
	}
	var secretPlan secrets.Secret
	err = json.Unmarshal(secretBytes, &secretPlan)
	if err != nil {
		return nil, err
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
			return nil, fmt.Errorf("cannot %s", msg)
		}
	}

	operation, err := startOperation(ctx, tx, i.secretId, instanceId, operationName, parameters)
	if err != nil {
		return nil, err
	}
	err = commit()
	if err != nil {
		return nil, err
	}

	instance := &secrets.Instance{
		Id:     instanceId,
		Status: operation.Status,
		Secret: secretPlan,
	}

	i.launchAsync(instance, operation, parameters, stdio)
	return instance, nil
}

func (i *InstanceRepository) launchAsync(instance *secrets.Instance, operation secrets.Operation, parameters executor.OperationParameters, stdio command.Stdio) {
	execCtx, cancel := context.WithCancel(context.Background())
	rt := &operationRuntime{done: make(chan struct{}), cancel: cancel}
	key := operationKey{instance.Id, operation.OperationNumber}
	i.mu.Lock()
	i.operations[key] = rt
	i.mu.Unlock()

	db := i.db
	secretId := i.secretId
	inst := instance
	go func() {
		defer close(rt.done)
		completeOperation(execCtx, db, secretId, inst, operation, parameters, stdio)
	}()
}

func (i *InstanceRepository) Await(ctx context.Context, instanceId string, operationNumber int) (*secrets.Instance, error) {
	key := operationKey{instanceId, operationNumber}
	i.mu.Lock()
	rt := i.operations[key]
	i.mu.Unlock()

	if rt != nil {
		select {
		case <-rt.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	instance, err := i.Get(ctx, instanceId)
	if err != nil {
		return nil, err
	}
	if instance.Status.OperationNumber < operationNumber {
		return instance, &store.UnknownOperationError{
			Expected: operationNumber,
			Latest:   instance.Status.OperationNumber,
		}
	}
	if instance.Status.OperationNumber > operationNumber {
		return instance, &store.StaleOperationError{
			Expected: operationNumber,
			Latest:   instance.Status.OperationNumber,
		}
	}
	return instance, nil
}

func (i *InstanceRepository) Cancel(ctx context.Context, instanceId string, operationNumber int) error {
	key := operationKey{instanceId, operationNumber}
	i.mu.Lock()
	rt := i.operations[key]
	i.mu.Unlock()

	if rt != nil {
		rt.cancel()
		select {
		case <-rt.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return fmt.Errorf("operation %d not running", operationNumber)
}

func startOperation(ctx context.Context, tx *sql.Tx, secretId string, instanceId string, operationName secrets.OperationName, paramaters executor.OperationParameters) (secrets.Operation, error) {
	operation := secrets.Operation{
		SecretId:   secretId,
		InstanceId: instanceId,
		Status: secrets.Status{
			Name:      operationName,
			Forced:    paramaters.Forced,
			Reason:    paramaters.Reason,
			StartedBy: paramaters.StartedBy,
		},
	}
	err := tx.QueryRowContext(ctx, `
		INSERT INTO operation (secretId, instanceId, name, forced, reason, startedBy, startedAt)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			RETURNING id, startedAt
	`, secretId, instanceId, operation.Name, operation.Forced, operation.Reason, operation.StartedBy, time.Now()).Scan(&operation.OperationNumber, &operation.StartedAt)
	return operation, err
}

func completeOperation(ctx context.Context, db *sql.DB, secretId string, instance *secrets.Instance, operation secrets.Operation, parameters executor.OperationParameters, stdio command.Stdio) error {
	processErr := executor.Execute(ctx, &instance.Secret, operation.Name, stdio, parameters, operation.InstanceId)

	tx, commit, rollback, err := beginTx(db)
	if err != nil {
		return err
	}
	defer rollback()

	// always set active instance on attempt to activate
	if operation.Name == secrets.Activate {
		tx.ExecContext(ctx, `
			UPDATE secret SET activeInstanceId = ?
			WHERE id = ?
		`, instance.Id, secretId)
	}

	err = processErr
	if err != nil {
		commitErr := tx.QueryRowContext(ctx, `
			UPDATE operation SET failedAt = ?
			WHERE id = ?
			RETURNING failedAt
		`, time.Now(), operation.OperationNumber).Scan(&instance.Status.FailedAt)
		if commitErr != nil {
			err = commitErr
		}
	} else {
		// only unset active instance on successful deactivate
		if operation.Name == secrets.Deactivate {
			tx.ExecContext(ctx, `
				UPDATE secret SET activeInstanceId = NULL
				WHERE id = ?
			`, secretId)
		}

		err = tx.QueryRowContext(ctx, `
			UPDATE operation SET completedAt = ?
			WHERE id = ?
			RETURNING completedAt
		`, time.Now(), operation.OperationNumber).Scan(&instance.Status.CompletedAt)
	}
	if err != nil {
		return err
	}

	return commit()
}

func (i *InstanceRepository) History(ctx context.Context, instanceId string, startAt int, endAt int) ([]*secrets.Operation, error) {
	rows, err := i.db.QueryContext(ctx, `
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
			failedAt
		FROM operation
		WHERE instanceId = ?
		LIMIT ? OFFSET ?
	`, instanceId, endAt-startAt, startAt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	operations := []*secrets.Operation{}
	for err == nil && rows.Next() {
		operation := &secrets.Operation{}
		operations = append(operations, operation)
		err = rows.Scan(&operation.OperationNumber, &operation.SecretId, &operation.InstanceId, &operation.Name, &operation.Forced, &operation.Reason, &operation.StartedBy, &operation.StartedAt, &operation.CompletedAt, &operation.FailedAt)
	}
	return operations, err
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
