package server

import (
	"fmt"
	"net/http"
)

type ErrorResponse struct {
	HttpError *httpError        `json:"error,omitempty"`
	Headers   map[string]string `json:"-"`
}

type httpError struct {
	Code    int    `json:"status"`
	Message string `json:"message"`
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
