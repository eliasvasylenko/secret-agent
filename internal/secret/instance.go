package secret

import (
	"errors"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// A provisioned instance of a secret
type Instance struct {
	// The ID of the secret instance
	id string

	// The plan for managing this secret
	plan *Plan

	// The DB for instance state
	store Store
}

type Instances map[string]*Instance

func LoadInstances(name *string, store Store) (Instances, error) {
	return nil, nil
}

func CreateInstance(id string, plan *Plan, store Store) (*Instance, error) {
	i := &Instance{id, plan, store}
	err := i.process(
		"creation",
		func(s Store, name string, id string) (func() error, error) { return s.CreateInstance(plan, id) },
		func(p *Plan) *command.Command { return p.Create },
	)
	return i, err
}

func (i *Instance) Destroy(force bool) error {
	id, _, err := i.store.ReadActiveInstance(i.id)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(id == i.id, force, "destroy instance while not inactive"); err != nil {
		return err
	}
	return i.process(
		"destruction",
		Store.DestroyInstance,
		func(p *Plan) *command.Command { return p.Destroy },
	)
}

func (i *Instance) Activate(force bool) error {
	id, completed, err := i.store.ReadActiveInstance(i.id)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(id == i.id && completed, force, "activate instance while active"); err != nil {
		return err
	}
	return i.process(
		"activation",
		Store.ActivateInstance,
		func(p *Plan) *command.Command { return p.Activate },
	)
}

func (i *Instance) Deactivate(force bool) error {
	id, _, err := i.store.ReadActiveInstance(i.id)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(id != i.id, force, "deactivate instance while inactive"); err != nil {
		return err
	}
	return i.process(
		"deactivation",
		Store.DeactivateInstance,
		func(p *Plan) *command.Command { return p.Deactivate },
	)
}

func (i *Instance) Test(force bool) error {
	activeId, complete, err := i.store.ReadActiveInstance(i.plan.Name)
	if err != nil {
		return fmt.Errorf("failed to read active instance - %v", err.Error())
	}
	if err := forceCheck(activeId != i.id || !complete, force, "test instance while not active"); err != nil {
		return err
	}
	return i.plan.process("", func(p *Plan) *command.Command { return p.Test })
}

func (i *Instance) process(operation string, start func(Store, string, string) (func() error, error), command func(*Plan) *command.Command) error {
	complete, err := start(i.store, i.plan.Name, i.id)
	if err != nil {
		return fmt.Errorf("failed to start %s of instance - %v", operation, err.Error())
	}
	err = i.plan.process("", command)
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
