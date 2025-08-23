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
	Line        []string    `json:"line"`
	exec        *func(name string, arg ...string) *exec.Cmd
}

func New(environment Environment, line []string) *Command {
	return &Command{
		Environment: environment,
		Line:        line,
		exec:        &execCommand,
	}
}

func (c *Command) UnmarshalJSON(p []byte) error {
	err1 := json.Unmarshal(p, &c.Line)
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
		return json.Marshal(c.Line)
	}
	type command Command
	return json.Marshal(command(*c))
}

func (c *Command) Process(input string) (string, error) {
	if len(c.Line) == 0 {
		return "", fmt.Errorf("command line is empty")
	}

	args := make([]string, 0)
	name := c.Environment.Expand(c.Line[0])
	for _, arg := range c.Line[1:] {
		args = append(args, c.Environment.Expand(arg))
	}

	subProcess := (*c.exec)(name, args...)
	subProcess.Env = append(subProcess.Env, c.Environment.Render()...)
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
