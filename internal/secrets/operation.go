package secrets

import (
	"time"
)

// Operation is one transition attempt: the edge of the instance lifecycle.
// On an instance it is the last operation that started, and Id is empty —
// the operation id identifies the ephemeral workflow, not the durable snapshot.
type Operation struct {
	Id         string        `json:"id,omitempty"`
	SecretId   string        `json:"secretId,omitempty"`
	InstanceId string        `json:"instanceId,omitempty"`
	Name       OperationName `json:"name"`
	Forced     bool          `json:"forced,omitzero"`
	Reason     string        `json:"reason,omitzero"`

	CreatedBy string    `json:"createdBy,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitzero"`

	StartedBy   string     `json:"startedBy,omitempty"`
	StartedAt   *time.Time `json:"startedAt,omitempty"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
	FailedAt    *time.Time `json:"failedAt,omitempty"`
}

// State is the lifecycle node the instance is in, and when it was entered.
type State struct {
	Name      StateName `json:"name,omitempty"`
	EnteredAt time.Time `json:"enteredAt,omitzero"`
}

// An operation which may be performed on a secret instance.
type OperationName string

const (
	Create     OperationName = "create"
	Destroy    OperationName = "destroy"
	Activate   OperationName = "activate"
	Deactivate OperationName = "deactivate"
	Test       OperationName = "test"
)

// StateName names a lifecycle node. Proposed is where an instance stays from
// the moment its row exists until create completes. Every other name is the
// node a successful operation enters.
type StateName string

const (
	Proposed    StateName = "proposed"
	Created     StateName = "create"
	Destroyed   StateName = "destroy"
	Activated   StateName = "activate"
	Deactivated StateName = "deactivate"
	Tested      StateName = "test"
)

var operationTargetStates = map[OperationName]StateName{
	Create:     Created,
	Destroy:    Destroyed,
	Activate:   Activated,
	Deactivate: Deactivated,
	Test:       Tested,
}

// TargetState is the node a successful operation enters.
func TargetState(name OperationName) (StateName, bool) {
	state, ok := operationTargetStates[name]
	return state, ok
}
