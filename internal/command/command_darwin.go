//go:build darwin

package command

import "os/exec"

const defaultShell = "zsh"

type CommandOptions struct {
}

func (o CommandOptions) Apply(subProcess *exec.Cmd) {
}
