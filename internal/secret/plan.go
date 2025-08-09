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
	Environment command.Environment `json:"environment"`

	// Create a new instance of the secret
	Create *command.Command `json:"create"`

	// Destroy an instance of the secret
	Destroy *command.Command `json:"destroy"`

	// Activate an instance of the secret
	Activate *command.Command `json:"activate"`

	// Deactivate an instance of the secret
	Deactivate *command.Command `json:"deactivate"`

	// Test the active secret
	Test *command.Command `json:"test"`

	// Successive plans
	Plans Plans `json:"plans"`
}

type Plans map[string]*Plan

func (s *Plans) UnmarshalJSON(p []byte) error {
	plans := make([]*Plan, 0)
	if err := json.Unmarshal(p, &plans); err != nil {
		return err
	}
	*s = make(map[string]*Plan)
	for _, plan := range plans {
		(*s)[plan.Name] = plan
	}
	return nil
}

func (s *Plans) MarshalJSON() ([]byte, error) {
	plans := make([]*Plan, len(*s))
	for _, plan := range *s {
		plans = append(plans, plan)
	}
	return json.Marshal(plans)
}

func (p *Plan) process(input string, command func(*Plan) *command.Command) error {
	output, err := command(p).Process(input)
	if err != nil {
		return err
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
