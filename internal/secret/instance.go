package secret

// A provisioned instance of a secret
type Instance struct {
	// The ID of the secret instance
	Id string `json:"id,omitempty"`

	// The plan for managing this secret
	Secret Secret `json:"secret"`

	// The current status of the instance, indicated by the last operation performed
	Status Status `json:"status"`
}

type Instances map[string]*Instance
