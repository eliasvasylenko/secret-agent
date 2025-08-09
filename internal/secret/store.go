package secret

/*
An interface for the storage of secret provisioning state
*/
type Store interface {
	// Start activating the instance with the given ID, returning a function to complete the operation
	ActivateInstance(name string, id string) (complete func() error, err error)
	// Start deactivating the instance with the given ID, returning a function to complete the operation
	DeactivateInstance(name string, id string) (complete func() error, err error)
	// Get the ID and status of the active instance of the secret with the given name
	ReadActiveInstance(name string) (id string, activateComplete bool, err error)

	// Start creating a new instance with the given plan and ID, returning a function to complete the operation
	CreateInstance(plan *Plan, id string) (complete func() error, err error)
	// Start destroying the instance with the given ID, returning a function to complete the operation
	DestroyInstance(name string, id string) (complete func() error, err error)
	// Get the plan and status of the instance with the given ID
	ReadInstance(name string, id string) (plan *Plan, createComplete bool, err error)
	// List the instance IDs for the plan with the given name
	ReadInstances(name string) (ids []string, err error)
}
