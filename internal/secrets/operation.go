package secrets

import (
	"time"
)

// The status of a secret instance at a point in time
type Operation struct {
	SecretId   string `json:"secretId"`
	InstanceId string `json:"instanceId"`
	Status     `json:""`
}

// An operation which may be performed on a secret instance
type OperationName string

// Proposal is set on the parent operation while Propose is blocked.
// It names the child op John must approve. Cleared when Propose returns.
type Proposal struct {
	ID              string        `json:"id"`
	SecretID        string        `json:"secretId,omitempty"`
	InstanceID      string        `json:"instanceId,omitempty"`
	OperationNumber int           `json:"operationNumber,omitempty"`
	Name            OperationName `json:"name"`
	At              string        `json:"at,omitempty"`
}

type Status struct {
	OperationNumber int           `json:"operationNumber"`
	Name            OperationName `json:"name"`
	Forced          bool          `json:"forced,omitzero"`
	Reason          string        `json:"reason,omitzero"`
	StartedBy       string        `json:"startedBy"`
	StartedAt       time.Time     `json:"startedAt"`
	CompletedAt     *time.Time    `json:"completedAt,omitempty"`
	FailedAt        *time.Time    `json:"failedAt,omitempty"`
	// ApprovalRequired is frozen at accept when the starter is a delegating parent.
	ApprovalRequired bool `json:"approvalRequired,omitempty"`
	// AwaitingApproval is true while that hold has not been released.
	AwaitingApproval bool `json:"awaitingApproval,omitempty"`
	// ApprovedBy is the principal who released the hold. It remains after the op finishes.
	ApprovedBy string `json:"approvedBy,omitempty"`
	// Proposal is set on the parent while its script is blocked in Propose.
	Proposal *Proposal `json:"proposal,omitempty"`
}

const (
	Create     OperationName = "create"
	Destroy    OperationName = "destroy"
	Activate   OperationName = "activate"
	Deactivate OperationName = "deactivate"
	Test       OperationName = "test"
)
