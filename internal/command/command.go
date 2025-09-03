package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Default function to execute a command
var execCommand = exec.Command

// A command to execute.
// A command consists of the name of the program to run, the arguments to pass to the program, and the environment to supply to the program.
type Command struct {
	Environment Environment `json:"environment"`
	Script      string      `json:"script"`
	exec        *func(name string, arg ...string) *exec.Cmd
}

func New(environment Environment, script string) *Command {
	return &Command{
		Environment: environment,
		Script:      script,
		exec:        &execCommand,
	}
}

func (c *Command) UnmarshalJSON(p []byte) error {
	err1 := json.Unmarshal(p, &c.Script)
	if err1 == nil {
		c.exec = &execCommand
		return nil
	}
	type command Command
	var temp command
	err2 := json.Unmarshal(p, &temp)
	if err2 != nil {
		return errors.Join(err1, err2)
	}
	*c = Command(temp)
	c.exec = &execCommand
	return nil
}

func (c *Command) MarshalJSON() ([]byte, error) {
	if len(c.Environment) == 0 {
		return json.Marshal(c.Script)
	}
	type command Command
	return json.Marshal(command(*c))
}

func (c *Command) Process(input string, environment Environment) (string, error) {
	env := c.Environment.Merge(environment)

	subProcess := (*c.exec)("bash", "-c", c.Script)
	subProcess.Env = append(subProcess.Env, env.Render([]string{})...)
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("resource could not be created '%v'", c)
	}
	defer stdin.Close()

	subProcess.Stdin = strings.NewReader(input)
	subProcess.Stderr = os.Stderr

	output, err := subProcess.Output()
	if err != nil {
		return "", fmt.Errorf("process failed '%v'", c)
	}

	return string(output), err
}
