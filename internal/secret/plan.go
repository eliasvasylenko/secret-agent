package secret

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

// A plan for the provisioning of a secret
type Plan struct {
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

	// Successive plans
	Plans Plans `json:"plans,omitempty"`
}

type Plans map[string]*Plan

func (s *Plans) UnmarshalJSON(p []byte) error {
	plans := make([]Plan, 0)
	if err := json.Unmarshal(p, &plans); err != nil {
		return err
	}
	*s = map[string]*Plan{}
	for _, plan := range plans {
		if plan.Name == "" {
			panic(string(p))
		}
		(*s)[plan.Name] = &plan
	}
	return nil
}

func (s *Plans) MarshalJSON() ([]byte, error) {
	plans := make([]*Plan, 0)
	for _, plan := range *s {
		plans = append(plans, plan)
	}
	return json.Marshal(plans)
}

func (p *Plan) process(input string, command func(*Plan) *command.Command) error {
	var output string

	cmd := command(p)
	if cmd != nil {
		commandOutput, err := cmd.Process(input)
		if err != nil {
			return err
		}
		output = commandOutput
	} else {
		output = ""
	}

	return p.processSubsteps(output, command)
}

func (p *Plan) processSubsteps(input string, command func(*Plan) *command.Command) error {
	for _, plan := range p.Plans {
		if err := plan.process(input, command); err != nil {
			return err
		}
	}
	return nil
}

func LoadPlans(plansFileName string) (Plans, error) {
	plansFile, err := os.Open(plansFileName)
	if err != nil {
		return Plans{}, err
	}

	plansBytes, err := io.ReadAll(plansFile)
	if err != nil {
		return Plans{}, err
	}

	var plans []*Plan
	err = json.Unmarshal(plansBytes, &plans)
	if err != nil {
		return Plans{}, err
	}

	planMap := make(map[string]*Plan)
	for _, plan := range plans {
		if plan.Name == "" {
			return Plans{}, fmt.Errorf("Plan name must not be empty")
		}
		if _, ok := planMap[plan.Name]; ok {
			return Plans{}, fmt.Errorf("Plan name '%s' must be unique", plan.Name)
		}
		planMap[plan.Name] = plan
	}
	return planMap, nil
}
