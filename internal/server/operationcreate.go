package server

import (
	"github.com/eliasvasylenko/secret-agent/internal/secret"
)

type OperationCreate struct {
	Name                       secret.OperationName `json:"name"`
	secret.OperationParameters `json:""`
}
