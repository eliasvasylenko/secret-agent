package secret

/*
An interface for the storage of secret provisioning state
*/
type InstanceStore interface {
	// Start activating the instance with the given ID, returning a function to complete the operation
	Activate(name string, id string, force bool) (complete func() error, err error)
	// Start deactivating the instance with the given ID, returning a function to complete the operation
	Deactivate(name string, id string, force bool) (complete func() error, err error)
	// Get the ID and status of the active instance of the secret with the given name
	ReadActive(name string) (id *string, activating bool, deactivating bool, err error)

	// Start creating a new instance with the given plan and ID, returning a function to complete the operation
	Create(id string, plan []byte, name string) (complete func() error, err error)
	// Start destroying the instance with the given ID, returning a function to complete the operation
	Destroy(id string, force bool) (complete func() error, err error)
	// Get the plan and status of the instance with the given ID
	Read(id string) (plan []byte, name string, creating bool, destroying bool, err error)

	// List the instance IDs for the plan with the given name
	List(name string) (ids []string, err error)
	// List all instance IDs
	ListAll() (ids []string, err error)
}
