package server

import (
	"fmt"
	"net/http"
)

type ErrorResponse struct {
	Err *err `json:"error,omitempty"`
}

type err struct {
	Message string `json:"message"`
	Code    int    `json:"status"`
}

func NewErrorResponse(message string, code int) *ErrorResponse {
	return &ErrorResponse{Err: &err{Message: message, Code: code}}
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("%s (%v) - %s", http.StatusText(r.Err.Code), r.Err.Code, r.Err.Message)
}
