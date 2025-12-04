package server

import (
	"fmt"
	"net/http"
)

type ErrorResponse struct {
	HttpError *httpError `json:"error,omitempty"`
}

type httpError struct {
	Message string `json:"message"`
	Code    int    `json:"status"`
}

func NewErrorResponse(err error, code int) *ErrorResponse {
	return &ErrorResponse{HttpError: &httpError{Message: err.Error(), Code: code}}
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%s (%v) - %s", http.StatusText(r.HttpError.Code), r.HttpError.Code, r.HttpError.Message)
}
