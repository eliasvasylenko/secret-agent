package config

import (
	"encoding/json"
	"io"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type Secrets struct {
	Secrets secrets.Secrets `json:"secrets"`
}

func LoadSecretsConfig(secretsFileName string) (*Secrets, error) {
	secretsFile, err := os.Open(secretsFileName)
	if err != nil {
		return &Secrets{}, err
	}

	secretsBytes, err := io.ReadAll(secretsFile)
	if err != nil {
		return &Secrets{}, err
	}

	var secrets Secrets
	err = json.Unmarshal(secretsBytes, &secrets)

	return &secrets, err
}
