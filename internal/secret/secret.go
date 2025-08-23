package secret

import (
	"encoding/json"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/google/uuid"
)

type Secret struct {
	// unique name of the secret
	Name string `json:"name"`

	// The plan for provisioning the secret
	Plan *Plan `json:"plan"`

	// The current instances of the secret
	Instances Instances `json:"instances,omitempty"`

	// The DB for instance state
	store InstanceStore
}

type Secrets map[string]*Secret

func Load(plansFileName string, name string, store InstanceStore) (*Secret, error) {
	plans, err := LoadPlans(plansFileName)
	if err != nil {
		return nil, err
	}
	plan := plans[name]

	instances, err := LoadPlanInstances(name, store)
	if err != nil {
		return nil, err
	}

	return &Secret{name, plan, instances, store}, nil
}

func LoadAll(plansFileName string, store InstanceStore) (Secrets, error) {
	plans, err := LoadPlans(plansFileName)
	if err != nil {
		return nil, err
	}

	secrets := make(map[string]*Secret)
	for name, plan := range plans {
		secrets[plan.Name] = &Secret{name, plan, make(map[string]*Instance), store}
	}

	instances, err := LoadAllInstances(store)
	if err != nil {
		return nil, err
	}
	for _, instance := range instances {
		plan := instance.Plan
		name := plan.Name
		secret, ok := secrets[name]
		if !ok {
			secret = &Secret{name, nil, make(map[string]*Instance), store}
		}
		secret.Instances[instance.Id] = instance
		secrets[instance.Plan.Name] = secret
	}

	return secrets, nil
}

func (s *Secret) Rotate(force bool) error {
	if s.Plan == nil {
		return fmt.Errorf("Cannot rotate orphaned secret.")
	}
	id := uuid.NewString()
	instance, err := CreateInstance(id, *s.Plan, s.store)
	s.Instances[id] = instance
	if err != nil {
		return err
	}
	//active := s.Active()
	//active.Deactivate(force)
	instance.Activate(force)
	return s.Plan.process("", func(p *Plan) *command.Command { return p.Create })
}

func (s *Secret) Show() error {
	bytes, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(bytes))
	return err
}

func (s Secrets) List() error {
	bytes, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(bytes))
	return err
}
