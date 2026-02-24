package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

// The function to execute a command
var processCommand = (*command.Command).Process

type Secrets map[string]*Secret

// A plan for the provisioning of a secret.
type Secret struct {
	// The name of the secret
	Name string `json:"name"`

	// The environment variables for the secret plan
	Environment command.Environment `json:"environment,omitempty"`

	// Create an instance of the secret
	Create *command.Command `json:"create,omitempty"`

	// Destroy an instance of the secret
	Destroy *command.Command `json:"destroy,omitempty"`

	// Activate an instance of the secret
	Activate *command.Command `json:"activate,omitempty"`

	// Deactivate an instance of the secret
	Deactivate *command.Command `json:"deactivate,omitempty"`

	// Test an instance of the secret
	Test *command.Command `json:"test,omitempty"`
}

func New(secretList []*Secret) (Secrets, error) {
	secrets := map[string]*Secret{}
	for _, secret := range secretList {
		if secret.Name == "" {
			return nil, fmt.Errorf("Secret name must not be empty")
		}
		if _, ok := secrets[secret.Name]; ok {
			return nil, fmt.Errorf("Secret name '%s' must be unique", secret.Name)
		}
		secrets[secret.Name] = secret
	}
	return secrets, nil
}

func (s *Secrets) UnmarshalJSON(p []byte) error {
	secretMap := make([]*Secret, 0)
	if err := json.Unmarshal(p, &secretMap); err != nil {
		return err
	}
	secrets, err := New(secretMap)
	*s = secrets
	return err
}

func (s Secrets) MarshalJSON() ([]byte, error) {
	secrets := make([]*Secret, 0)
	for _, secret := range s {
		secrets = append(secrets, secret)
	}
	return marshal.JSON(secrets)
}

func (s *Secret) Command(operation OperationName) *command.Command {
	switch operation {
	case Create:
		return s.Create
	case Destroy:
		return s.Destroy
	case Activate:
		return s.Activate
	case Deactivate:
		return s.Deactivate
	case Test:
		return s.Test
	default:
		return nil
	}
}

func (s *Secret) Process(ctx context.Context, operation OperationName, input string, parameters OperationParameters, instanceId string) error {
	parameters.Env = s.Environment.ExpandAndMergeWith(command.Environment{
		"ID":         instanceId,
		"NAME":       s.Name,
		"FORCE":      strconv.FormatBool(parameters.Forced),
		"REASON":     parameters.Reason,
		"STARTED_BY": parameters.StartedBy,
	}).ExpandWith(parameters.Env)

	cmd := s.Command(operation)
	if cmd != nil {
		_, err := processCommand(cmd, ctx, input, parameters.Env)
		return err
	}
	return nil
}
