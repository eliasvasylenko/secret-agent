package cli

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/client"
	"github.com/eliasvasylenko/secret-agent/internal/config"
	"github.com/eliasvasylenko/secret-agent/internal/sqlite"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
)

// It's plainly silly that Go requires these structs.
type clientSecrets struct {
	*client.SecretClient
}

func (s clientSecrets) Instances(secretId string) backend.Instances {
	return s.SecretClient.Instances(secretId)
}

func NewStore(ctx context.Context, socket string, secretsFile string, dbFile string, debug bool, maxReasonLen int) (backend.Backend, error) {
	if socket != "" {
		store := client.NewSecretStore(socket)
		return clientSecrets{
			SecretClient: store,
		}, nil
	} else {
		secretsConfig, err := config.LoadSecretsConfig(secretsFile)
		if err != nil {
			return nil, err
		}
		return sqlite.Open(ctx, dbFile, secretsConfig.Secrets, debug, maxReasonLen)
	}
}
