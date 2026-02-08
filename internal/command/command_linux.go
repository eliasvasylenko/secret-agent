//go:build linux

package command

import (
	"os/exec"
	"syscall"
)

const defaultShell = "bash"

type CommandOptions struct {
	Credential *syscall.Credential `json:"credential,omitempty"`
}

func (o CommandOptions) Apply(subProcess *exec.Cmd) {
	subProcess.SysProcAttr = &syscall.SysProcAttr{}
	if o.Credential != nil {
		subProcess.SysProcAttr.Credential = o.Credential
	}
}
