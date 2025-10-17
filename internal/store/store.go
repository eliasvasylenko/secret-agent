package store

import (
	"context"

	"github.com/eliasvasylenko/secret-agent/internal/client"
	"github.com/eliasvasylenko/secret-agent/internal/secret"
	"github.com/eliasvasylenko/secret-agent/internal/sqlite"
)

type Config struct {
	Socket      string
	SecretsFile string
	DbFile      string
	Debug       bool
}

type Secrets interface {
	// List all secrets
	List(ctx context.Context) (secret.Secrets, error)

	// Get the secret with the given id
	Get(ctx context.Context, secretId string) (*secret.Secret, error)

	// Read the active instance of the secret with the given secret id
	GetActive(ctx context.Context, secretId string) (*secret.Instance, error)

	// Read the operation history of a secret, from the given inclusive index, to the given exclusive index
	History(ctx context.Context, secretId string, from int, to int) ([]*secret.Operation, error)

	// The interfaces of the secret with the given id
	Instances(secretId string) Instances
}

type Instances interface {
	// List all instances
	List(ctx context.Context, from int, to int) (secret.Instances, error)

	// Get the instance with the given ID
	Get(ctx context.Context, instanceId string) (*secret.Instance, error)

	// Start creating a new instance with the given plan and ID, returning a function to complete the operation
	Create(ctx context.Context, parameters secret.OperationParameters) (*secret.Instance, error)

	// Start destroying the instance with the given ID, returning a function to complete the operation
	Destroy(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error)

	// Activate the instance with the given ID and secret name
	Activate(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error)

	// Deactivate the instance with the given ID and secret name
	Deactivate(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error)

	// Deactivate the instance with the given ID and secret name
	Test(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error)

	// Read the operation history of a secret instance, from the given inclusive index, to the given exclusive index
	History(ctx context.Context, instanceId string, from int, to int) ([]*secret.Operation, error)
}

// It's plainly silly that Go requires these structs.
type clientSecrets struct {
	*client.SecretClient
}

func (s clientSecrets) Instances(secretId string) Instances {
	return s.SecretClient.Instances(secretId)
}

type sqliteSecrets struct {
	*sqlite.SecretRespository
}

func (s sqliteSecrets) Instances(secretId string) Instances {
	return s.SecretRespository.Instances(secretId)
}

// Create a new store instance from config
func New(ctx context.Context, config Config) (Secrets, error) {
	if config.Socket != "" {
		secrets := client.NewSecretStore(config.Socket)
		return clientSecrets{
			SecretClient: secrets,
		}, nil
	} else {
		plans, err := secret.LoadSecrets(config.SecretsFile)
		if err != nil {
			return nil, err
		}
		secrets, err := sqlite.NewSecretRepository(ctx, config.DbFile, plans, config.Debug)
		return sqliteSecrets{
			SecretRespository: secrets,
		}, err
	}
}
