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

// A plan for the provisioning of a secret
type Secret struct {
	// The name of the secret
	Name string `json:"name"`

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

	// Derive sub-secrets
	Derive Secrets `json:"derive,omitempty"`
}

type Secrets map[string]*Secret

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
	var output string

	qname := s.Name
	if parent, ok := parameters.Env["QNAME"]; ok {
		qname = fmt.Sprintf("%s/%s", parent, qname)
	}
	qid := fmt.Sprintf("%s/%s", qname, instanceId)
	env := s.Environment.ExpandAndMergeWith(map[string]string{
		"ID":         instanceId,
		"NAME":       s.Name,
		"QID":        qid,
		"QNAME":      qname,
		"FORCE":      strconv.FormatBool(parameters.Forced),
		"REASON":     parameters.Reason,
		"STARTED_BY": parameters.StartedBy,
	}).ExpandWith(parameters.Env)

	command := s.Command(operation)
	if command != nil {
		commandOutput, err := processCommand(command, ctx, input, env)
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
	}, instanceId)
}

func (s *Secret) processSubsteps(ctx context.Context, operation OperationName, input string, parameters OperationParameters, instanceId string) error {
	for _, secret := range s.Derive {
		if err := secret.Process(ctx, operation, input, parameters, instanceId); err != nil {
			return err
		}
	}
	return nil
}
