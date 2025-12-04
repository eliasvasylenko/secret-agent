package server

import "github.com/eliasvasylenko/secret-agent/internal/secrets"

type OperationCreate struct {
	Name                        secrets.OperationName `json:"name"`
	secrets.OperationParameters `json:""`
}
