package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"database/sql"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
)

// An instance store implementation backed by sqlite
type SecretRespository struct {
	db      *sql.DB
	secrets secrets.Secrets
}

type InstanceRepository struct {
	db       *sql.DB
	secretId string
	secret   *secrets.Secret
}

// The lifecycle status of an instance
type instanceStatus string

const (
	created    instanceStatus = "created"
	creating   instanceStatus = "creating"
	destroying instanceStatus = "destroying"
)

func NewSecretRepository(ctx context.Context, dbFile string, secrets secrets.Secrets, debug bool) (*SecretRespository, error) {
	db, err := sql.Open("sqlite3", dbFile)
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS instance (
			id TEXT NOT NULL PRIMARY KEY,
			secretId TEXT NOT NULL,
			secret JSONB NOT NULL,
			FOREIGN KEY(secretId) REFERENCES secret(id)
		);
		CREATE TABLE IF NOT EXISTS secret (
			id TEXT NOT NULL PRIMARY KEY,
			activeInstanceId TEXT,
			FOREIGN KEY(activeInstanceId) REFERENCES instance(id)
		);
		CREATE TABLE IF NOT EXISTS operation (
			id INTEGER PRIMARY KEY,
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
	return &SecretRespository{db, secrets}, err
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
	operations := []*secrets.Operation{}
	for err == nil && rows.Next() {
		operation := &secrets.Operation{}
		operations = append(operations, operation)
		err = rows.Scan(&operation.Id, &operation.SecretId, &operation.InstanceId, &operation.Name, &operation.Forced, &operation.Reason, &operation.StartedBy, &operation.StartedAt, &operation.CompletedAt, &operation.FailedAt)
	}
	return operations, err
}

func (s *SecretRespository) Instances(secretId string) *InstanceRepository {
	secret := s.secrets[secretId]
	return &InstanceRepository{
		db:       s.db,
		secretId: secretId,
		secret:   secret,
	}
}

func (i *InstanceRepository) List(ctx context.Context, from int, to int) (secrets.Instances, error) {
	rows, err := i.db.QueryContext(ctx, `
		SELECT
			i.id,
			i.secret,
			o.name,
			o.forced,
			o.reason,
			o.startedBy,
			o.startedAt,
			o.completedAt,
			o.failedAt
		FROM instance i
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE i.secretId = ?
	`, i.secretId)
	instances := secrets.Instances{}
	for err == nil && rows.Next() {
		instance := &secrets.Instance{}
		var secretBytes []byte
		err = rows.Scan(&instance.Id, &secretBytes, &instance.Status.Name, &instance.Status.Forced, &instance.Status.Reason, &instance.Status.StartedBy, &instance.Status.StartedAt, &instance.Status.CompletedAt, &instance.Status.FailedAt)
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
			i.secret,
			o.name,
			o.forced,
			o.reason,
			o.startedBy,
			o.startedAt,
			o.completedAt,
			o.failedAt
		FROM instance i
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE i.id = ?
	`, instanceId).Scan(&secretBytes, &instance.Status.Name, &instance.Status.Forced, &instance.Status.Reason, &instance.Status.StartedBy, &instance.Status.StartedAt, &instance.Status.CompletedAt, &instance.Status.FailedAt)
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
			i.secret,
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
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE s.id = ?
	`, i.secretId)
	if err != nil || !rows.Next() {
		return nil, err
	}

	var secretBytes []byte
	var instance = &secrets.Instance{}
	err = rows.Scan(&instance.Id, &secretBytes, &instance.Status.Name, &instance.Status.Forced, &instance.Status.Reason, &instance.Status.StartedBy, &instance.Status.StartedAt, &instance.Status.CompletedAt, &instance.Status.FailedAt)
	if err != nil {
		return nil, err
	}
	return instance, json.Unmarshal(secretBytes, &instance.Secret)
}

func (i *InstanceRepository) Create(ctx context.Context, paramaters secrets.OperationParameters) (*secrets.Instance, error) {
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

	secretBytes, err := marshal.JSON(i.secret)
	if err != nil {
		return nil, err
	}

	instanceId := uuid.NewString()
	_, err = tx.ExecContext(ctx, `
			INSERT INTO instance(id, secretId, secret)
				VALUES(?, ?, ?)
		`, instanceId, i.secretId, secretBytes)
	if err != nil {
		return nil, err
	}

	operation, err := startOperation(ctx, tx, i.secretId, instanceId, secrets.Create, paramaters)
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

	err = completeOperation(ctx, i.db, i.secretId, instance, operation, paramaters)
	return instance, err
}

func (i *InstanceRepository) Destroy(ctx context.Context, instanceId string, paramaters secrets.OperationParameters) (*secrets.Instance, error) {
	return updateOperation(ctx, i.db, i.secretId, instanceId, secrets.Destroy, paramaters)
}

func (i *InstanceRepository) Activate(ctx context.Context, instanceId string, paramaters secrets.OperationParameters) (*secrets.Instance, error) {
	return updateOperation(ctx, i.db, i.secretId, instanceId, secrets.Activate, paramaters)
}

func (i *InstanceRepository) Deactivate(ctx context.Context, instanceId string, paramaters secrets.OperationParameters) (*secrets.Instance, error) {
	return updateOperation(ctx, i.db, i.secretId, instanceId, secrets.Deactivate, paramaters)
}

func (i *InstanceRepository) Test(ctx context.Context, instanceId string, paramaters secrets.OperationParameters) (*secrets.Instance, error) {
	return updateOperation(ctx, i.db, i.secretId, instanceId, secrets.Test, paramaters)
}

func updateOperation(ctx context.Context, db *sql.DB, secretId string, instanceId string, operationName secrets.OperationName, paramaters secrets.OperationParameters) (*secrets.Instance, error) {
	tx, commit, rollback, err := beginTx(db)
	if err != nil {
		return nil, err
	}
	defer rollback()

	var secretBytes []byte
	var activeInstanceId *string
	var previousOperation secrets.Operation
	err = tx.QueryRowContext(ctx, `
		SELECT
			i.secret,
			s.activeInstanceId,
			o.name,
			o.startedAt,
			o.completedAt,
			o.failedAt
		FROM instance i
		INNER JOIN secret s
			ON s.id = i.secretId
		INNER JOIN (
			SELECT MAX(id), *
			FROM operation
			GROUP BY instanceId
		) o
		 	ON o.instanceId = i.id
		WHERE i.id = ?
	`, instanceId).Scan(&secretBytes, &activeInstanceId, &previousOperation.Name, &previousOperation.StartedAt, &previousOperation.CompletedAt, &previousOperation.FailedAt)
	if err != nil {
		return nil, err
	}
	var secretPlan secrets.Secret
	err = json.Unmarshal(secretBytes, &secretPlan)
	if err != nil {
		return nil, err
	}

	var msg string

	if previousOperation.CompletedAt == nil && operationName != previousOperation.Name {
		msg = fmt.Sprintf("%s when previous %s has not succeeded", operationName, previousOperation.Name)
	} else if operationName == secrets.Activate && activeInstanceId != nil {
		msg = fmt.Sprintf("%s when instance %s is active", operationName, *activeInstanceId)
	} else if (operationName == secrets.Test || operationName == secrets.Deactivate) && (activeInstanceId == nil || *activeInstanceId != instanceId) {
		msg = fmt.Sprintf("%s when instance is not active", operationName)
	}

	if msg != "" {
		if paramaters.Forced {
			log.Default().Printf("forcing %s", msg)
		} else {
			return nil, fmt.Errorf("cannot %s", msg)
		}
	}

	println(secretId, instanceId, operationName, previousOperation.Name, activeInstanceId, string(secretBytes), msg)

	operation, err := startOperation(ctx, tx, secretId, instanceId, operationName, paramaters)
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

	err = completeOperation(ctx, db, secretId, instance, operation, paramaters)
	return instance, err
}

func startOperation(ctx context.Context, tx *sql.Tx, secretId string, instanceId string, operationName secrets.OperationName, paramaters secrets.OperationParameters) (secrets.Operation, error) {
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
		INSERT INTO operation (id, secretId, instanceId, name, forced, reason, startedBy, startedAt)
			VALUES (NULL, ?, ?, ?, ?, ?, ?, DATETIME('now'))
			RETURNING id, startedAt
	`, secretId, instanceId, operation.Name, operation.Forced, operation.Reason, operation.StartedBy).Scan(&operation.Id, &operation.StartedAt)
	return operation, err
}

func completeOperation(ctx context.Context, db *sql.DB, secretId string, instance *secrets.Instance, operation secrets.Operation, parameters secrets.OperationParameters) error {
	processErr := instance.Secret.Process(ctx, operation.Name, "", parameters, operation.InstanceId)

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
			UPDATE operation SET failedAt = DATETIME('now')
			WHERE id = ?
			RETURNING failedAt
		`, operation.Id).Scan(&instance.Status.FailedAt)
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
			UPDATE operation SET completedAt = DATETIME('now') 
			WHERE id = ?
			RETURNING completedAt
		`, operation.Id).Scan(&instance.Status.CompletedAt)
	}
	if err != nil {
		return err
	}

	return commit()
}

func (i *InstanceRepository) History(ctx context.Context, instanceId string, startAt int, endAt int) (operations []*secrets.Operation, err error) {
	var rows *sql.Rows
	rows, err = i.db.QueryContext(ctx, `
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
	for err == nil && rows.Next() {
		operation := &secrets.Operation{}
		operations = append(operations, operation)
		err = rows.Scan(&operation.Id, &operation.SecretId, &operation.InstanceId, &operation.Name, &operation.Forced, &operation.Reason, &operation.StartedBy, &operation.StartedAt, &operation.CompletedAt, &operation.FailedAt)
	}
	return
}
