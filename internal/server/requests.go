package server

import (
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

// OperationRequest is the JSON payload common to every operation request.
// Maps to executor.OperationParameters; server sets StartedBy from transport identity.
type OperationRequest struct {
	Env    command.Environment `json:"env"`
	Forced bool                `json:"forced"`
	Reason string              `json:"reason"`
}

// AttachRequest is one attach. Fds are the descriptors that share the
// file. Mode is what the process does with it.
type AttachRequest struct {
	Fds  []int            `json:"fds"`
	Mode command.FileMode `json:"mode"`
}

func (r AttachRequest) Validate() error {
	if !r.Mode.Valid() {
		return fmt.Errorf("unknown attach mode %q", r.Mode)
	}
	if len(r.Fds) == 0 {
		return fmt.Errorf("attach fds required")
	}
	seen := map[int]bool{}
	for _, fd := range r.Fds {
		if fd < 0 || fd > command.MaxFd {
			return fmt.Errorf("attach fd %d out of range", fd)
		}
		if seen[fd] {
			return fmt.Errorf("duplicate attach fd %d", fd)
		}
		seen[fd] = true
	}
	return nil
}

// StartOperationRequest creates an operation: POST /operations.
// Create operations carry SecretId and no InstanceId; other operations carry
// InstanceId (and derive their secret from it), with Name saying which.
type StartOperationRequest struct {
	SecretId         string                `json:"secretId,omitempty"`
	InstanceId       string                `json:"instanceId,omitempty"`
	Name             secrets.OperationName `json:"name"`
	OperationRequest `json:""`
}
