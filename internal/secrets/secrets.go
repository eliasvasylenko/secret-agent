package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

// A plan for the provisioning of a secret
type Secret struct {
	// The name of the secret
	Id string `json:"id"`

	// The environment variables for the secret plan
	Environment command.Environment `json:"environment,omitempty"`

	// Create a new instance of the secret
	Create *command.Command `json:"create,omitempty"`

	// Destroy an instance of the secret
	Destroy *command.Command `json:"destroy,omitempty"`

	// Activate an instance of the secret
	Activate *command.Command `json:"activate,omitempty"`

	// Deactivate an instance of the secret
	Deactivate *command.Command `json:"deactivate,omitempty"`

	// Test the active secret
	Test *command.Command `json:"test,omitempty"`

	// Derived secrets
	Derived Secrets `json:"derived,omitempty"`
}

type Secrets map[string]*Secret

func New(secretList []*Secret) (Secrets, error) {
	secrets := map[string]*Secret{}
	for _, secret := range secretList {
		if secret.Id == "" {
			return nil, fmt.Errorf("Secret ID must not be empty")
		}
		if _, ok := secrets[secret.Id]; ok {
			return nil, fmt.Errorf("Secret ID '%s' must be unique", secret.Id)
		}
		secrets[secret.Id] = secret
	}
	return secrets, nil
}

func (s *Secrets) UnmarshalJSON(p []byte) error {
	secretList := make([]*Secret, 0)
	if err := json.Unmarshal(p, &secretList); err != nil {
		return err
	}
	secrets, err := New(secretList)
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

func (s *Secret) Process(ctx context.Context, operation OperationName, input string, parameters OperationParameters) error {
	var output string
	env := parameters.Env

	path := s.Id
	if parent, ok := env["PATH"]; ok {
		path = fmt.Sprintf("%s/%s/", parent, path)
	}
	env = command.Environment{
		"PATH":       path,
		"NAME":       s.Id,
		"FORCE":      strconv.FormatBool(parameters.Forced),
		"REASON":     parameters.Reason,
		"STARTED_BY": parameters.StartedBy,
	}.Merge(env)

	command := s.Command(operation)
	if command != nil {
		commandOutput, err := command.Process(ctx, input, env)
		if err != nil {
			return err
		}
		output = commandOutput
	} else {
		output = ""
	}

	return s.processSubsteps(ctx, operation, output, OperationParameters{
		Env:       env,
		Forced:    parameters.Forced,
		Reason:    parameters.Reason,
		StartedBy: parameters.StartedBy,
	})
}

func (s *Secret) processSubsteps(ctx context.Context, operation OperationName, input string, parameters OperationParameters) error {
	for _, secret := range s.Derived {
		if err := secret.Process(ctx, operation, input, parameters); err != nil {
			return err
		}
	}
	return nil
}
