package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
	"golang.org/x/sys/unix"
)

const defaultShell = "bash"

// CommandOptions is how a script process is run. Credential, when set, is
// the uid and gid of that process.
type CommandOptions struct {
	Credential *syscall.Credential `json:"credential,omitempty"`
}

func (o CommandOptions) zero() bool {
	return o.Credential == nil
}

// ownTerminals sets the owner of each terminal slave to the process uid,
// so tools that reopen the terminal by name are not denied.
func ownTerminals(o CommandOptions, files Files) {
	if o.Credential == nil {
		return
	}
	for _, f := range files.Fds {
		if f != nil && Terminal(f) {
			_ = unix.Fchown(int(f.Fd()), int(o.Credential.Uid), int(o.Credential.Gid))
		}
	}
}

// The function to execute a command
var execCommand = exec.CommandContext

// A command to execute.
// A command consists of the name of the program to run, the arguments to pass to the program, and the environment to supply to the program.
type Command struct {
	Script      string      `json:"script"`
	Environment Environment `json:"environment"`
	Shell       string      `json:"shell"`
	CommandOptions
}

func New(script string, environment Environment, shell string) *Command {
	return &Command{
		Script:      script,
		Environment: environment,
		Shell:       shell,
	}
}

func (c *Command) UnmarshalJSON(p []byte) error {
	err1 := json.Unmarshal(p, &c.Script)
	if err1 == nil {
		return nil
	}
	type command Command
	var temp command
	err2 := json.Unmarshal(p, &temp)
	if err2 != nil {
		return errors.Join(err1, err2)
	}
	*c = Command(temp)
	return nil
}

func (c *Command) MarshalJSON() ([]byte, error) {
	// A bare script stays a JSON string. Shell or command options must use the
	// object form, or they are dropped when the plan is stored.
	if len(c.Environment) == 0 && c.Shell == "" && c.CommandOptions.zero() {
		return marshal.JSON(c.Script)
	}
	type command Command
	return marshal.JSON(command(*c))
}

func (c *Command) Process(ctx context.Context, files Files, environment Environment) error {
	env := c.Environment.ExpandAndMergeWith(environment)

	shell, args, err := BuildShellExec(c.Script, c.Shell)
	if err != nil {
		return err
	}

	subProcess := execCommand(ctx, shell, args...)
	subProcess.Env = append(subProcess.Env, env.Render()...)
	// Own session, so the script has no controlling terminal unless one is
	// installed below. Own process group, so cancel kills the whole group.
	subProcess.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: c.Credential}
	subProcess.Cancel = func() error {
		err := syscall.Kill(-subProcess.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}

	subProcess.Stdin = files.file(0)
	subProcess.Stdout = files.file(1)
	subProcess.Stderr = files.file(2)
	if len(files.Fds) > 3 {
		subProcess.ExtraFiles = files.Fds[3:]
	}

	if files.Tty >= 0 && files.file(files.Tty) != nil {
		subProcess.SysProcAttr.Setctty = true
		subProcess.SysProcAttr.Ctty = files.Tty
	}

	ownTerminals(c.CommandOptions, files)

	if err := subProcess.Start(); err != nil {
		return fmt.Errorf("process failed '%v' - %s", c, err.Error())
	}

	if err := subProcess.Wait(); err != nil {
		return fmt.Errorf("process failed '%v' - %s", c, err)
	}
	return nil
}
