package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

// Default function to execute a command
var execCommand = exec.CommandContext

// A command to execute.
// A command consists of the name of the program to run, the arguments to pass to the program, and the environment to supply to the program.
type Command struct {
	Script         string      `json:"script"`
	Environment    Environment `json:"environment"`
	Shell          string      `json:"shell"`
	CommandOptions `json:",omitempty"`
	exec           *func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

func New(script string, environment Environment, shell string) *Command {
	return &Command{
		Script:      script,
		Environment: environment,
		Shell:       shell,
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
		return marshal.JSON(c.Script)
	}
	type command Command
	return marshal.JSON(command(*c))
}

func (c *Command) Process(ctx context.Context, input string, environment Environment) (string, error) {
	env := c.Environment.ExpandAndMergeWith(environment)

	shell, args, err := BuildShellExec(c.Script, c.Shell)
	if err != nil {
		return "", err
	}

	subProcess := (*c.exec)(ctx, shell, args...)
	subProcess.Env = append(subProcess.Env, env.Render()...)
	c.CommandOptions.Apply(subProcess)
	stdin, err := subProcess.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("resource could not be created '%v'", c)
	}
	defer stdin.Close()

	subProcess.Stdin = strings.NewReader(input)
	subProcess.Stderr = os.Stderr

	output, err := subProcess.Output()
	if err != nil {
		return "", fmt.Errorf("process failed '%v' - %s", c, err.Error())
	}

	return string(output), err
}
