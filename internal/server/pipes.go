package server

import (
	"io"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

type operationPipes struct {
	stdinR  io.ReadCloser
	stdinW  io.WriteCloser
	stdoutR io.ReadCloser
	stdoutW io.WriteCloser
	stderrR io.ReadCloser
	stderrW io.WriteCloser
}

func newOperationPipes() (*operationPipes, command.Stdio) {
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	pipes := &operationPipes{
		stdinR:  stdinR,
		stdinW:  stdinW,
		stdoutR: stdoutR,
		stdoutW: stdoutW,
		stderrR: stderrR,
		stderrW: stderrW,
	}
	stdio := command.Stdio{
		Stdin:  stdinR,
		Stdout: stdoutW,
		Stderr: stderrW,
	}
	return pipes, stdio
}

func closeOperationPipes(p *operationPipes) {
	if p == nil {
		return
	}
	_ = p.stdinR.Close()
	_ = p.stdinW.Close()
	_ = p.stdoutR.Close()
	_ = p.stdoutW.Close()
	_ = p.stderrR.Close()
	_ = p.stderrW.Close()
}
