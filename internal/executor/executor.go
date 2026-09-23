package executor

import (
	"context"
	"fmt"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

var processCommand = (*command.Command).Process

// OperationParameters are the common parameters for an operation on a secret instance
type OperationParameters struct {
	Env                     command.Environment `json:"env"`
	Forced                  bool                `json:"forced"`
	Reason                  string              `json:"reason"`
	StartedBy               string              `json:"startedBy"`
	ExpectedOperationNumber *int                `json:"expectedOperationNumber,omitempty"`
}

// Validate enforces basic constraints
func (p OperationParameters) Validate(maxReasonLength int) error {
	reasonLength := len(p.Reason)
	if maxReasonLength > 0 && reasonLength > maxReasonLength {
		return fmt.Errorf("reason too long (%d exceeds max of %d bytes)", reasonLength, maxReasonLength)
	}
	return nil
}

// Execute runs the command for the given operation on the secret.
func Execute(ctx context.Context, secret *secrets.Secret, operation secrets.OperationName, stdio command.Stdio, parameters OperationParameters, instanceId string) error {
	parameters.Env = secret.Environment.ExpandAndMergeWith(command.Environment{
		"INSTANCE":   instanceId,
		"SECRET":     secret.Id,
		"FORCE":      strconv.FormatBool(parameters.Forced),
		"REASON":     parameters.Reason,
		"STARTED_BY": parameters.StartedBy,
	}).ExpandWith(parameters.Env)

	cmd := secret.Command(operation)
	if cmd != nil {
		return processCommand(cmd, ctx, stdio, parameters.Env)
	}
	return nil
}
