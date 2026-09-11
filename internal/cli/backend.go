package cli

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/client"
	"github.com/eliasvasylenko/secret-agent/internal/config"
	"github.com/eliasvasylenko/secret-agent/internal/sqlite"
)

func NewBackend(ctx context.Context, socket string, secretsFile string, dbFile string, debug bool, maxReasonLen int) (backend.Backend, error) {
	if socket != "" {
		return client.NewSecretStore(socket), nil
	}
	secretsConfig, err := config.LoadSecretsConfig(secretsFile)
	if err != nil {
		return nil, err
	}
	return sqlite.Open(ctx, dbFile, secretsConfig.Secrets, debug, maxReasonLen)
}
