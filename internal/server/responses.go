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

func NewErrorResponse(code int, err error) *ErrorResponse {
	return &ErrorResponse{HttpError: &httpError{Code: code, Message: err.Error()}, Headers: make(map[string]string)}
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

func writeBytes(ctx context.Context, w http.ResponseWriter, stream Stream, fromByte int, maxBytes int) error {
	data := make([]byte, maxBytes)
	reader := stream.Reader(ctx)
	n, err := reader.ReadAt(data, int64(fromByte))
	if err != nil && err != io.EOF {
		return writeError(w, err)
	}
	response := StreamResponse{Data: data[:n], Complete: err == io.EOF}
	return writeResult(w, response, http.StatusOK)
}
