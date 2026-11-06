package secrets

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

// A provisioned instance of a secret. Status is a snapshot: the established
// state, and the last operation that started.
type Instance struct {
	Id        string    `json:"id,omitempty"`
	Secret    Secret    `json:"secret"`
	Revision  int       `json:"revision"`
	State     State     `json:"state"`
	Operation Operation `json:"operation"`
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
	instanceList := make([]*Instance, 0)
	if err := json.Unmarshal(p, &instanceList); err != nil {
		return err
	}
	instances, err := NewInstances(instanceList)
	*i = instances
	return err
}

func (i Instances) MarshalJSON() ([]byte, error) {
	instances := make([]*Instance, 0)
	for _, instance := range i {
		instances = append(instances, instance)
	}
	slices.SortFunc(instances, func(a, b *Instance) int {
		if c := b.Operation.CreatedAt.Compare(a.Operation.CreatedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.Id, b.Id)
	})
	return marshal.JSON(instances)
}
