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

// SecretOperationRequest starts an operation on a secret: POST /instances.
// Create is the only such operation, so no name is carried.
type SecretOperationRequest struct {
	SecretId         string `json:"secretId"`
	OperationRequest `json:""`
}

// InstanceOperationRequest starts a named operation on an instance: POST /operations.
// The operation's secret is derived from InstanceId, never sent by the client.
type InstanceOperationRequest struct {
	InstanceId       string                `json:"instanceId"`
	Name             secrets.OperationName `json:"name"`
	OperationRequest `json:""`
}
