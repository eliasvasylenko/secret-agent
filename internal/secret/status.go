package secret

import "time"

type Status struct {
	Name        OperationName `json:"name"`
	Forced      bool          `json:"forced,omitzero"`
	Reason      string        `json:"reason,omitzero"`
	StartedBy   string        `json:"startedBy"`
	StartedAt   time.Time     `json:"startedAt"`
	CompletedAt *time.Time    `json:"completedAt,omitempty"`
	FailedAt    *time.Time    `json:"failedAt,omitempty"`
}
