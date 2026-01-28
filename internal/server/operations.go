package server

import (
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type OperationParameters struct {
	Env    command.Environment `json:"env"`
	Forced bool                `json:"forced"`
	Reason string              `json:"reason"`
}

type CreateOperationParameters struct {
	Name                secrets.OperationName `json:"name"`
	OperationParameters `json:""`
}
