package secret

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/command"
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
	DerivedSecrets Secrets `json:"derivedSecrets,omitempty"`
}

type Secrets map[string]*Secret

func LoadSecrets(secretsFileName string) (Secrets, error) {
	secretsFile, err := os.Open(secretsFileName)
	if err != nil {
		return Secrets{}, err
	}

	plansBytes, err := io.ReadAll(secretsFile)
	if err != nil {
		return Secrets{}, err
	}

	var secrets []*Secret
	err = json.Unmarshal(plansBytes, &secrets)
	if err != nil {
		return Secrets{}, err
	}

	secretMap := make(map[string]*Secret)
	for _, secret := range secrets {
		if secret.Id == "" {
			return Secrets{}, fmt.Errorf("Secret ID must not be empty")
		}
		if _, ok := secretMap[secret.Id]; ok {
			return Secrets{}, fmt.Errorf("Secret ID '%s' must be unique", secret.Id)
		}
		secretMap[secret.Id] = secret
	}
	return secretMap, nil
}

func (s *Secrets) UnmarshalJSON(p []byte) error {
	plans := make([]*Secret, 0)
	if err := json.Unmarshal(p, &plans); err != nil {
		return err
	}
	*s = map[string]*Secret{}
	for _, plan := range plans {
		if plan.Id == "" {
			panic(string(p))
		}
		(*s)[plan.Id] = plan
	}
	return nil
}

func (s Secrets) MarshalJSON() ([]byte, error) {
	plans := make([]*Secret, 0)
	for _, plan := range s {
		plans = append(plans, plan)
	}
	return json.Marshal(plans)
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
	for _, secret := range s.DerivedSecrets {
		if err := secret.Process(ctx, operation, input, parameters); err != nil {
			return err
		}
	}
	return nil
}
