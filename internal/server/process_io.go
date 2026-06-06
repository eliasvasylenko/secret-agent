package server

import (
	"fmt"
	"net/http"
)

type ExchangeIORequest struct {
	Stdin  *ExchangeBytes `json:"stdin,omitempty"`
	Stdout *ExchangeIndex `json:"stdout,omitempty"`
	Stderr *ExchangeIndex `json:"stderr,omitempty"`
}

type ExchangeIOResponse struct {
	Stdin  *ExchangeIndex `json:"stdin,omitempty"`
	Stdout *ExchangeBytes `json:"stdout,omitempty"`
	Stderr *ExchangeBytes `json:"stderr,omitempty"`

	ExitCode *int `json:"exitCode,omitempty"`
}

type ExchangeIndex struct {
	Index int64 `json:"index"`
}

type ExchangeBytes struct {
	Index  int64  `json:"index"`
	Bytes  []byte `json:"bytes,omitempty"`
	Closed bool   `json:"closed,omitempty"`
}

func validateStdinChunk(index int64, data []byte, maxBytes int64) error {
	if int64(len(data)) > maxBytes {
		return NewErrorResponse(http.StatusRequestEntityTooLarge,
			fmt.Errorf("stdin chunk exceeds maxBytes (%d)", maxBytes))
	}
	if index+int64(len(data)) > maxBytes {
		return NewErrorResponse(http.StatusRequestEntityTooLarge,
			fmt.Errorf("stdin write at %d with %d bytes exceeds maxBytes (%d)", index, len(data), maxBytes))
	}
	return nil
}

func exchangeStreamOut(index int64, chunk StreamResponse) *ExchangeBytes {
	if len(chunk.Data) == 0 && !chunk.Complete {
		return nil
	}
	return &ExchangeBytes{
		Index:  index,
		Bytes:  chunk.Data,
		Closed: chunk.Complete,
	}
}
