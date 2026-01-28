package secrets

import (
	"fmt"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// The status of a secret instance at a point in time
type Operation struct {
	SecretId   string `json:"secretId"`
	InstanceId string `json:"instanceId"`
	Status     `json:""`
}

// OperationParameters are the common parameters for an operation on a secret instance
type OperationParameters struct {
	Env       command.Environment `json:"env"`
	Forced    bool                `json:"forced"`
	Reason    string              `json:"reason"`
	StartedBy string              `json:"startedBy"`
}

// Validate enforces basic constraints
func (p OperationParameters) Validate(maxReasonLength int) error {
	reasonLength := len(p.Reason)
	if maxReasonLength > 0 && reasonLength > maxReasonLength {
		return fmt.Errorf("reason too long (%d exceeds max of %d bytes)", reasonLength, maxReasonLength)
	}
	return nil
}

// An operation which may be performed on a secret instance
type OperationName string

type Status struct {
	OperationNumber int           `json:"operationNumber"`
	Name            OperationName `json:"name"`
	Forced          bool          `json:"forced,omitzero"`
	Reason          string        `json:"reason,omitzero"`
	StartedBy       string        `json:"startedBy"`
	StartedAt       time.Time     `json:"startedAt"`
	CompletedAt     *time.Time    `json:"completedAt,omitempty"`
	FailedAt        *time.Time    `json:"failedAt,omitempty"`
}

const (
	Create     OperationName = "create"
	Destroy    OperationName = "destroy"
	Activate   OperationName = "activate"
	Deactivate OperationName = "deactivate"
	Test       OperationName = "test"
)
