package secrets

import (
	"encoding/json"
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

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

func NewInstances(instanceList []*Instance) (Instances, error) {
	instances := map[string]*Instance{}
	for _, instance := range instanceList {
		if instance.Id == "" {
			return nil, fmt.Errorf("Instance ID must not be empty")
		}
		if _, ok := instances[instance.Id]; ok {
			return nil, fmt.Errorf("Instance ID '%s' must be unique", instance.Id)
		}
		instances[instance.Id] = instance
	}
	return instances, nil
}

func (i *Instances) UnmarshalJSON(p []byte) error {
	instanceMap := make([]*Instance, 0)
	if err := json.Unmarshal(p, &instanceMap); err != nil {
		return err
	}
	instances, err := NewInstances(instanceMap)
	*i = instances
	return err
}

func (i Instances) MarshalJSON() ([]byte, error) {
	instances := make([]*Instance, 0)
	for _, instance := range i {
		instances = append(instances, instance)
	}
	return marshal.JSON(instances)
}
