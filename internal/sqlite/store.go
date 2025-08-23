package sqlite

import (
	"context"
	"fmt"
	"log"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

type InstanceStore struct {
	db *sql.DB
}

type instanceStatus string

const (
	created    instanceStatus = "created"
	creating   instanceStatus = "creating"
	destroying instanceStatus = "destroying"
)

type activeStatus string

const (
	activated    activeStatus = "activated"
	activating   activeStatus = "activating"
	deactivating activeStatus = "deactivating"
	deactivated  activeStatus = "deactivated"
)

func NewStore(debug bool) *InstanceStore {
	db, err := sql.Open("sqlite3", "./instances.db")
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS instances (
			id VARCHAR(128) NOT NULL PRIMARY KEY,
			name VARCHAR(1024),
			plan JSONB NOT NULL,
			status VARCHAR(32)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			name VARCHAR(1024) NOT NULL PRIMARY KEY,
			id VARCHAR(128),
			status VARCHAR(32)
		)
	`)
	if err != nil {
		log.Fatal(err)
	}
	return &InstanceStore{db}
}

func (s *InstanceStore) Close() {
	s.db.Close()
}

func (s *InstanceStore) Activate(name string, id string, force bool) (func() error, error) {
	err := s.updateSecret(name, &id, nil, activating, deactivated, force)
	return func() error {
		return s.updateSecret(name, &id, &id, activated, activating, false)
	}, err
}

func (s *InstanceStore) Deactivate(name string, id string, force bool) (func() error, error) {
	err := s.updateSecret(name, &id, &id, deactivating, activated, force)
	return func() error {
		return s.updateSecret(name, nil, &id, deactivated, deactivating, false)
	}, err
}

func (s *InstanceStore) ReadActive(name string) (*string, bool, bool, error) {
	id, status, err := s.readActive(name)
	if err != nil {
		return nil, false, false, err
	}
	return id, status == activating, status == deactivating, nil
}

func (s *InstanceStore) readActive(name string) (*string, activeStatus, error) {
	var id *string
	var status activeStatus
	err := s.db.QueryRow(`
		SELECT id, status FROM secrets
		WHERE name = ?
	`, name).Scan(&id, &status)
	return id, status, err
}

func (s *InstanceStore) updateSecret(name string, id *string, priorId *string, status activeStatus, priorStatus activeStatus, force bool) error {
	result, err := s.db.Exec(`
		UPDATE secrets SET id = ?, status = ?
		WHERE name = ?
		AND id = ?
		AND (status = ? OR ?)
	`, id, status, name, priorId, priorStatus, force)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("Failed to update status of %s from %s to %s", name, priorStatus, status)
	}
	return err
}

func (s *InstanceStore) Create(id string, plan []byte, name string) (func() error, error) {
	err := s.createInstance(plan, name, id)
	if err != nil {
		return nil, err
	}
	return func() error {
		err := s.updateInstance(id, created, creating, false)
		return err
	}, nil
}

func (s *InstanceStore) Destroy(id string, force bool) (func() error, error) {
	err := s.updateInstance(id, destroying, created, force)
	var name string
	err = s.db.QueryRow(`
		SELECT name FROM instances
		WHERE id = ?
	`, id).Scan(&name)
	if err != nil {
		return nil, err
	}
	return func() error {
		tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelDefault})
		if err != nil {
			return err
		}
		tx.Exec(`
			DELETE * FROM instances
			WHERE id = ?
		`, id)
		tx.Exec(`
			DELETE * FROM secrets
			WHERE name = ?
		`, name)
		return tx.Commit()
	}, nil
}

func (s *InstanceStore) Read(id string) ([]byte, string, bool, bool, error) {
	plan, name, status, err := s.readInstance(id)
	return plan, name, status == creating, status == destroying, err
}

func (s *InstanceStore) List(name string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT id FROM instances
		WHERE name = ?
	`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, err
}

func (s *InstanceStore) ListAll() ([]string, error) {
	rows, err := s.db.Query(`
		SELECT id FROM instances
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		err = rows.Scan(&id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, err
}

func (s *InstanceStore) createInstance(plan []byte, name string, id string) error {
	_, err := s.db.Exec(`
		INSERT INTO instances(id, name, plan, status) VALUES(?, ?, ?, ?)
	`, id, name, plan, creating)
	return err
}

func (s *InstanceStore) readInstance(id string) ([]byte, string, instanceStatus, error) {
	var plan []byte
	var name string
	var status instanceStatus
	err := s.db.QueryRow(`
		SELECT plan, name, status FROM instances
		WHERE id = ?
	`, id).Scan(&plan, &name, &status)
	if err != nil {
		return nil, "", "", err
	}
	return plan, name, status, err
}

func (s *InstanceStore) updateInstance(id string, status instanceStatus, priorStatus instanceStatus, force bool) error {
	// result, err := s.db.Query(`
	// 	UPDATE instances SET status = ?
	// 	WHERE id = ?
	// 	AND (status = ? OR ?)
	// 	AND (
	// 		SELECT id FROM secrets WHERE name = plan->>'name'
	// 	) != id
	// 	RETURNING status
	// `, status, id, priorStatus, force)
	// if err != nil {
	// 	return err
	// }
	// var oldStatus instanceStatus
	// err = result.Scan(&oldStatus)

	result, err := s.db.Exec(`
		UPDATE instances SET status = ?
		WHERE id = ?
		AND (status = ? OR ?)
		AND NOT EXISTS(
			SELECT 1 FROM secrets s WHERE s.name = name AND s.id = id
		)
		RETURNING status
	`, status, id, priorStatus, force)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("Failed to update status of %s from %s to %s", id, priorStatus, status)
	}
	return nil
}
