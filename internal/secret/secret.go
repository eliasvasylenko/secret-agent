package secret

import (
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

type Secret struct {
	// unique name of the secret
	name string

	// The plan for provisioning the secret
	plan *Plan

	// The current instances of the secret
	instances map[string]*Instance

	// The DB for instance state
	store Store
}

type Secrets map[string]*Secret

func Load(plansFileName string, name string, store Store) (*Secret, error) {
	plans, err := LoadPlans(plansFileName)
	if err != nil {
		return nil, err
	}
	plan := plans[name]

	instances, err := LoadInstances(&name, store)
	if err != nil {
		return nil, err
	}

	return &Secret{name, plan, instances, store}, nil
}

func LoadAll(plansFileName string, store Store) (Secrets, error) {
	plans, err := LoadPlans(plansFileName)
	if err != nil {
		return nil, err
	}

	secrets := make(map[string]*Secret)
	for name, plan := range plans {
		secrets[plan.Name] = &Secret{name, plan, make(map[string]*Instance), store}
	}

	instances, err := LoadInstances(nil, store)
	if err != nil {
		return nil, err
	}
	for _, instance := range instances {
		plan := instance.plan
		name := plan.Name
		secret, ok := secrets[name]
		if !ok {
			secret = &Secret{name, plan, make(map[string]*Instance), store}
		}
		secret.instances[instance.id] = instance
		secrets[instance.plan.Name] = secret
	}

	return secrets, nil
}

func (s *Secret) Show() error {
	_, err := fmt.Println(s.name, s)
	return err
}

func (s *Secret) Rotate() error {
	return s.plan.process("", func(p *Plan) *command.Command { return p.Create })
}

func (s Secrets) List() error {
	for _, secret := range s {
		_, err := fmt.Println(secret.name, secret)
		if err != nil {
			return err
		}
	}
	return nil
}
