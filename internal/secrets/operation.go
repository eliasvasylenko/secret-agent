package secrets

import (
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// The status of a secret instance at a point in time
type Operation struct {
	Id         int    `json:"id"`
	SecretId   string `json:"secretId"`
	InstanceId string `json:"instanceId"`
	Status     `json:""`
}

type OperationParameters struct {
	Env       command.Environment `json:"env"`
	Forced    bool                `json:"forced"`
	Reason    string              `json:"reason"`
	StartedBy string              `json:"startedBy"`
}

// An operation which may be performed on a secret instance
type OperationName string

type Status struct {
	Name        OperationName `json:"name"`
	Forced      bool          `json:"forced,omitzero"`
	Reason      string        `json:"reason,omitzero"`
	StartedBy   string        `json:"startedBy"`
	StartedAt   time.Time     `json:"startedAt"`
	CompletedAt *time.Time    `json:"completedAt,omitempty"`
	FailedAt    *time.Time    `json:"failedAt,omitempty"`
}

const (
	Create     OperationName = "create"
	Destroy    OperationName = "destroy"
	Activate   OperationName = "activate"
	Deactivate OperationName = "deactivate"
	Test       OperationName = "test"
)
