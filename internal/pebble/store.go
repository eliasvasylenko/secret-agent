package pebble

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/cockroachdb/pebble"
	"github.com/eliasvasylenko/secret-agent/internal/secret"
)

type Store struct {
	client *pebble.DB
}

type instance struct {
	Status instanceStatus `json:"status"`
}

type instanceStatus string

const (
	created    instanceStatus = "created"
	creating   instanceStatus = "creating"
	destroying instanceStatus = "destroying"
)

type active struct {
	Id     string       `json:"id"`
	Status activeStatus `json:"status"`
}

type activeStatus string

const (
	activated    activeStatus = "activated"
	activating   activeStatus = "activating"
	deactivating activeStatus = "deactivating"
	deactivated  activeStatus = "deactivated"
)

func NewStore() *Store {
	client, err := pebble.Open("state", &pebble.Options{})
	if err != nil {
		log.Fatal(err)
	}
	return &Store{client}
}

func (s *Store) ActivateInstance(name string, id string) (func() error, error) {
	err := s.writeActive(name, active{Id: id, Status: activating})
	return func() error {
		return s.writeActive(name, active{Id: id, Status: activated})
	}, err
}

func (s *Store) DeactivateInstance(name string, id string) (func() error, error) {
	err := s.writeActive(name, active{Id: id, Status: deactivating})
	return func() error {
		return s.writeActive(name, active{Id: "", Status: deactivated})
	}, err
}

func (s *Store) ReadActiveInstance(name string) (string, bool, error) {
	a, err := s.readActive(name)
	if err != nil {
		return "", false, err
	}
	return a.Id, a.Status == activated, nil
}

func (s *Store) readActive(name string) (active, error) {
	key := key("secret/%s/active", name)
	activeBytes, closer, err := s.client.Get(key)
	if err != nil {
		return active{}, err
	}
	defer closer.Close()
	var a active
	err = json.Unmarshal(activeBytes, &a)
	return a, err
}

func (s *Store) writeActive(name string, a active) error {
	key := key("secret/%s/active", name)
	activeBytes, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.client.Set(key, activeBytes, pebble.Sync)
}

func (s *Store) CreateInstance(plan *secret.Plan, id string) (func() error, error) {
	err := s.writePlan(plan, id)
	if err != nil {
		return nil, err
	}
	err = s.writeInstance(plan.Name, id, instance{Status: creating})
	if err != nil {
		return nil, err
	}
	return func() error {
		return s.writeInstance(plan.Name, id, instance{Status: created})
	}, nil
}

func (s *Store) DestroyInstance(name string, id string) (func() error, error) {
	err := s.writeInstance(name, id, instance{Status: destroying})
	if err != nil {
		return nil, err
	}
	return func() error {
		return s.client.DeleteRange(
			key("secret/%s/instance/%s/", name, id),
			key("secret/%s/instance/%s0", name, id),
			pebble.Sync,
		)
	}, nil
}

func (s *Store) ReadInstance(name string, id string) (*secret.Plan, bool, error) {
	plan, err := s.readPlan(name, id)
	if err != nil {
		return nil, false, err
	}
	i, err := s.readInstance(name, id)
	return plan, i.Status == created, err
}

func (s *Store) ReadInstances(name string) ([]string, error) {
	ids := make([]string, 0)
	iter, err := s.client.NewIter(&pebble.IterOptions{
		LowerBound: key("secret/%s/", name),
		UpperBound: key("secret/%s0", name),
		SkipPoint: func(userKey []byte) bool {
			return !strings.HasSuffix(string(userKey), "/plan")
		},
	})
	if err != nil {
		return nil, err
	}
	for valid := iter.First(); valid; valid = iter.Next() {
		key := string(iter.Key())
		id := key[strings.LastIndex(key, "/")+1:]
		ids = append(ids, id)
	}
	if err := iter.Close(); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Store) readPlan(name string, id string) (*secret.Plan, error) {
	key := key("secret/%s/instance/%s/plan", name, id)
	planBytes, closer, err := s.client.Get(key)
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	var plan *secret.Plan
	err = json.Unmarshal(planBytes, &plan)
	if err != nil {
		return nil, err
	}
	return plan, nil
}

func (s *Store) writePlan(plan *secret.Plan, id string) error {
	key := key("secret/%s/instance/%s/plan", plan.Name, id)
	planBytes, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	return s.client.Set(key, planBytes, pebble.Sync)
}

func (s *Store) readInstance(name string, id string) (instance, error) {
	key := key("secret/%s/instance/%s/status", name, id)
	instanceBytes, closer, err := s.client.Get(key)
	if err != nil {
		return instance{}, err
	}
	defer closer.Close()
	var i instance
	err = json.Unmarshal(instanceBytes, &i)
	if err != nil {
		return instance{}, err
	}
	return i, nil
}

func (s *Store) writeInstance(name string, id string, i instance) error {
	key := key("secret/%s/instance/%s/status", name, id)
	instanceBytes, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return s.client.Set(key, instanceBytes, pebble.Sync)
}

func key(format string, s ...string) []byte {
	replacer := strings.NewReplacer("/", "\\/", "\\", "\\\\")
	escaped := make([]any, len(s))
	for _, s := range s {
		escaped = append(escaped, replacer.Replace(s))
	}
	return []byte(fmt.Sprintf(format, escaped...))
}
