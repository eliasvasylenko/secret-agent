package server

import (
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

// StartOperationRequest creates an operation: POST /operations.
// Create operations carry SecretId and no InstanceId; other operations carry
// InstanceId (and derive their secret from it), with Name saying which.
type StartOperationRequest struct {
	SecretId         string                `json:"secretId,omitempty"`
	InstanceId       string                `json:"instanceId,omitempty"`
	Name             secrets.OperationName `json:"name"`
	OperationRequest `json:""`
}
