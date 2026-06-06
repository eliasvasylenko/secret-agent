package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type ItemsResponse[T any] struct {
	Items T `json:"items"`
}

type ErrorResponse struct {
	HttpError *httpError        `json:"error,omitempty"`
	Headers   map[string]string `json:"-"`
}

type httpError struct {
	Code    int    `json:"status"`
	Message string `json:"message"`
}

type StreamResponse struct {
	Data     []byte `json:"data,omitempty"`
	Complete bool   `json:"complete"`
}

// StdioResponse is returned by POST .../operations/{opNumber}/stdio.
type StdioResponse struct {
	Stdout StreamResponse `json:"stdout"`
	Stderr StreamResponse `json:"stderr"`
}

func NewErrorResponse(code int, err error) *ErrorResponse {
	var message string
	if err != nil {
		message = err.Error()
	} else {
		message = http.StatusText(code)
	}
	return &ErrorResponse{HttpError: &httpError{Code: code, Message: message}, Headers: make(map[string]string)}
}

func (r *ErrorResponse) Error() string {
	if r.HttpError.Message == "" {
		return fmt.Sprintf("%v %s", r.HttpError.Code, http.StatusText(r.HttpError.Code))
	} else {
		return fmt.Sprintf("%v %s - %s", r.HttpError.Code, http.StatusText(r.HttpError.Code), r.HttpError.Message)
	}
}

func writeResult(w http.ResponseWriter, value any, statusCode int) error {
	w.WriteHeader(statusCode)

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(value)
	if err != nil {
		return err
	}

	return nil
}

func writeError(w http.ResponseWriter, err error) error {
	var response *ErrorResponse
	if errors.As(err, &response) {
		for key, value := range response.Headers {
			w.Header().Set(key, value)
		}
	} else {
		response = NewErrorResponse(
			http.StatusInternalServerError,
			err,
		)
	}
	return writeResult(w, response, response.HttpError.Code)
}

func readStreamChunk(ctx context.Context, stream Stream, fromByte int64, maxBytes int64) (StreamResponse, error) {
	data := make([]byte, maxBytes)
	reader := stream.AsyncReader(ctx)
	n, err := reader.ReadAt(data, fromByte)
	if err == io.EOF {
		return StreamResponse{Data: data[:n], Complete: true}, nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return StreamResponse{Data: data[:n], Complete: false}, nil
	}
	if err != nil {
		return StreamResponse{}, err
	}
	return StreamResponse{Data: data[:n], Complete: false}, nil
}
