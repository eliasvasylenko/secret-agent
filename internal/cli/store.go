package cli

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/client"
	"github.com/eliasvasylenko/secret-agent/internal/config"
	"github.com/eliasvasylenko/secret-agent/internal/sqlite"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

// It's plainly silly that Go requires these structs.
type clientSecrets struct {
	*client.SecretClient
}

func (s clientSecrets) Instances(secretId string) store.Instances {
	return s.SecretClient.Instances(secretId)
}

type sqliteSecrets struct {
	*sqlite.SecretRespository
}

func (s sqliteSecrets) Instances(secretId string) store.Instances {
	return s.SecretRespository.Instances(secretId)
}

func NewStore(ctx context.Context, socket string, secretsFile string, dbFile string, debug bool, maxReasonLen int) (store.Secrets, error) {
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
		store, err := sqlite.NewSecretRepository(ctx, dbFile, secretsConfig.Secrets, debug, maxReasonLen)
		return sqliteSecrets{
			SecretRespository: store,
		}, err
	}
}
