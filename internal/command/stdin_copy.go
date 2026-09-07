package command

import "io"

func stopStdinCopy(_ io.Reader, stdinPipe io.WriteCloser) {
	if stdinPipe != nil {
		_ = stdinPipe.Close()
	}
}
