package secret

import (
	"encoding/json"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// A provisioned instance of a secret
type Instance struct {
	// The ID of the secret instance
	Id string `json:"id,omitempty"`

	// The plan for managing this secret
	Plan Plan `json:"plan"`

	// The plan for managing this secret
	Status InstanceStatus `json:"status"`

	// The DB for instance state
	store InstanceStore
}

type InstanceStatus string

const (
	Creating     InstanceStatus = "creating"
	Destroying   InstanceStatus = "destroying"
	Active       InstanceStatus = "active"
	Inactive     InstanceStatus = "inactive"
	Activating   InstanceStatus = "activating"
	Deactivating InstanceStatus = "deactivating"
)

type Instances map[string]*Instance

func LoadPlanInstances(name string, store InstanceStore) (Instances, error) {
	ids, err := store.List(name)
	if err != nil {
		return nil, fmt.Errorf("failed to list instances - %v", err.Error())
	}
	return LoadInstances(ids, store)
}

func LoadAllInstances(store InstanceStore) (Instances, error) {
	ids, err := store.ListAll()
	if err != nil {
		return nil, fmt.Errorf("failed to list instances - %v", err.Error())
	}
	return LoadInstances(ids, store)
}

func LoadInstances(ids []string, store InstanceStore) (Instances, error) {
	instances := make(Instances)
	names := make(map[string]struct{})
	for _, id := range ids {
		planText, name, creating, destroying, err := store.Read(id)
		status := Inactive
		if destroying {
			status = Destroying
		} else if creating {
			status = Creating
		}
		names[name] = struct{}{}
		if err != nil {
			return nil, fmt.Errorf("failed to read instance - %v", err.Error())
		}
		var plan Plan
		err = json.Unmarshal(planText, &plan)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal instance plan - %v", err.Error())
		}
		instances[id] = &Instance{
			Id:     id,
			Plan:   plan,
			Status: status,
			store:  store,
		}
	}
	for name := range names {
		active, activating, deactivating, err := store.ReadActive(name)
		if err != nil {
			return nil, fmt.Errorf("failed to read active instance - %v", err.Error())
		}
		if activating {
			instances[*active].Status = Activating
		} else if deactivating {
			instances[*active].Status = Deactivating
		} else if active != nil {
			instances[*active].Status = Active
		}
	}
	return instances, nil
}

func CreateInstance(id string, plan Plan, store InstanceStore) (*Instance, error) {
	planText, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	i := &Instance{id, plan, Inactive, store}
	err = i.process(
		"creation",
		Inactive,
		false,
		func(s InstanceStore, name string, id string, force bool) (func() error, error) {
			return s.Create(id, planText, name)
		},
		func(p *Plan) *command.Command { return p.Create },
	)
	return i, err
}

func (i *Instance) Destroy(force bool) error {
	return i.process(
		"destroy",
		Inactive,
		force,
		func(s InstanceStore, name, id string, force bool) (func() error, error) { return s.Destroy(id, force) },
		func(p *Plan) *command.Command { return p.Destroy },
	)
}

func (i *Instance) Activate(force bool) error {
	err := i.process(
		"activate",
		Inactive,
		force,
		InstanceStore.Activate,
		func(p *Plan) *command.Command { return p.Activate },
	)
	if err == nil {
		i.Status = Active
	}
	return err
}

func (i *Instance) Deactivate(force bool) error {
	err := i.process(
		"deactivate",
		Active,
		force,
		InstanceStore.Deactivate,
		func(p *Plan) *command.Command { return p.Deactivate },
	)
	if err == nil {
		i.Status = Inactive
	}
	return err
}

func (i *Instance) Test(force bool) error {
	return i.process("test", Active, force, nil, func(p *Plan) *command.Command { return p.Test })
}

func (i *Instance) Show(pretty bool) error {
	var bytes []byte
	var err error
	if pretty {
		bytes, err = json.MarshalIndent(i, "", "  ")
	} else {
		bytes, err = json.Marshal(i)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(bytes))
	return err
}

func (i *Instance) process(operation string, condition InstanceStatus, force bool, start func(InstanceStore, string, string, bool) (func() error, error), cmd func(*Plan) *command.Command) error {
	if err := i.forceCheck(operation, condition, force); err != nil {
		return err
	}
	var complete func() error
	if start != nil {
		completeFunction, err := start(i.store, i.Plan.Name, i.Id, force)
		if err != nil {
			return fmt.Errorf("failed to start %s of instance - %v", operation, err.Error())
		}
		complete = completeFunction
	}
	env := command.Environment{"ID": i.Id}
	if err := i.Plan.process("", env, cmd); err != nil {
		return fmt.Errorf("failed to process %s of instance - %v", operation, err.Error())
	}
	if complete != nil {
		if err := complete(); err != nil {
			return fmt.Errorf("failed to complete %s of instance - %v", operation, err.Error())
		}
	}
	return nil
}

func (i *Instance) forceCheck(operation string, condition InstanceStatus, force bool) error {
	if i.Status == condition {
		return nil
	} else if force {
		return fmt.Errorf("forcing %s instance while %s", operation, i.Status)
	} else {
		return fmt.Errorf("cannot %s instance while %s", operation, i.Status)
	}
}
