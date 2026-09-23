package server

import (
	"io"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

type attachPipes struct {
	stdinR  io.ReadCloser
	stdinW  io.WriteCloser
	stdoutR io.ReadCloser
	stdoutW io.WriteCloser
	stderrR io.ReadCloser
	stderrW io.WriteCloser
}

func newAttachPipes() *attachPipes {
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	stderrR, stderrW := io.Pipe()
	return &attachPipes{
		stdinR:  stdinR,
		stdinW:  stdinW,
		stdoutR: stdoutR,
		stdoutW: stdoutW,
		stderrR: stderrR,
		stderrW: stderrW,
	}
}

func (p *attachPipes) Stdio() command.Stdio {
	return command.Stdio{
		Stdin:  p.stdinR,
		Stdout: p.stdoutW,
		Stderr: p.stderrW,
	}
}

func closeAttachPipes(p *attachPipes) {
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
