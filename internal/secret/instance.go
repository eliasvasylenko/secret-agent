package secret

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// A provisioned instance of a secret
type Instance struct {
	// The ID of the secret instance
	Id string `json:"id,omitempty"`

	// The plan for managing this secret
	Plan Plan `json:"plan,omitempty"`

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
			return nil, err
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
		false,
		func(s InstanceStore, name string, id string, force bool) (func() error, error) {
			return s.Create(id, planText, name)
		},
		func(p *Plan) *command.Command { return p.Create },
	)
	return i, err
}

func (i *Instance) Destroy(force bool) error {
	id, _, _, err := i.store.ReadActive(i.Id)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(id != nil && *id == i.Id, force, "destroy instance while not inactive"); err != nil {
		return err
	}
	return i.process(
		"destruction",
		force,
		func(s InstanceStore, name, id string, force bool) (func() error, error) { return s.Destroy(id, force) },
		func(p *Plan) *command.Command { return p.Destroy },
	)
}

func (i *Instance) Activate(force bool) error {
	id, activating, deactivating, err := i.store.ReadActive(i.Id)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(id != nil && *id == i.Id && !activating && !deactivating, force, "activate instance while active"); err != nil {
		return err
	}
	return i.process(
		"activation",
		force,
		InstanceStore.Activate,
		func(p *Plan) *command.Command { return p.Activate },
	)
}

func (i *Instance) Deactivate(force bool) error {
	id, _, _, err := i.store.ReadActive(i.Id)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(id == nil || *id != i.Id, force, "deactivate instance while inactive"); err != nil {
		return err
	}
	return i.process(
		"deactivation",
		force,
		InstanceStore.Deactivate,
		func(p *Plan) *command.Command { return p.Deactivate },
	)
}

func (i *Instance) Test(force bool) error {
	id, activating, deactivating, err := i.store.ReadActive(i.Plan.Name)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(id == nil || *id != i.Id || activating || deactivating, force, "test instance while not active"); err != nil {
		return err
	}
	return i.Plan.process("", func(p *Plan) *command.Command { return p.Test })
}

func (i *Instance) process(operation string, force bool, start func(InstanceStore, string, string, bool) (func() error, error), command func(*Plan) *command.Command) error {
	complete, err := start(i.store, i.Plan.Name, i.Id, force)
	if err != nil {
		return fmt.Errorf("failed to start %s of instance - %v", operation, err.Error())
	}
	err = i.Plan.process("", command)
	if err != nil {
		return fmt.Errorf("failed to process %s of instance - %v", operation, err.Error())
	}
	err = complete()
	if err != nil {
		return fmt.Errorf("failed to complete %s of instance - %v", operation, err.Error())
	}
	return nil
}

func forceCheck(condition bool, force bool, message string) error {
	if !condition {
		return nil
	} else if force {
		return errors.New("force check not implemented yet") // TODO are you sure you want to $message?
	} else {
		return fmt.Errorf("cannot %s", message)
	}
}
