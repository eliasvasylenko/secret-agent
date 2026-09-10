package server

import (
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

// OperationRequest is the JSON body for POST …/instances (create).
// Maps to executor.OperationParameters; server sets StartedBy from transport identity.
type OperationRequest struct {
	Env    command.Environment `json:"env"`
	Forced bool                `json:"forced"`
	Reason string              `json:"reason"`
}

// NamedOperationRequest is OperationRequest plus name for POST …/instances/{id}/operations.
type NamedOperationRequest struct {
	Name             secrets.OperationName `json:"name"`
	OperationRequest `json:""`
}
