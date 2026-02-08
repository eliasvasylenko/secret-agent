//go:build windows

package command

import "os/exec"

const defaultShell = "powershell"

type CommandOptions struct {
}

func (o CommandOptions) Apply(subProcess *exec.Cmd) {
}
