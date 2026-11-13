package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

type ItemsResponse[T any] struct {
	Items T `json:"items"`
}

// OperationCreatedResponse answers POST /operations: a pending operation.
type OperationCreatedResponse struct {
	OperationID string    `json:"operationId"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expiresAt"`
}

// OperationStatusResponse answers GET /operations/{operationId}.
type OperationStatusResponse struct {
	Operation secrets.Operation `json:"operation"`
	State     string            `json:"state"`
	ExpiresAt time.Time         `json:"expiresAt,omitzero"`
	Instance  *secrets.Instance `json:"instance,omitempty"`
}

type ErrorResponse struct {
	HttpError *httpError        `json:"error,omitempty"`
	Headers   map[string]string `json:"-"`
}

type httpError struct {
	Code    int    `json:"status"`
	Message string `json:"message"`
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
	}
	return fmt.Sprintf("%v %s - %s", r.HttpError.Code, http.StatusText(r.HttpError.Code), r.HttpError.Message)
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
		response = NewErrorResponse(statusFor(err), err)
	}
	return writeResult(w, response, response.HttpError.Code)
}

func statusFor(err error) int {
	var (
		secretNotFound   *backend.SecretNotFoundError
		instanceNotFound *backend.InstanceNotFoundError
		revisionMismatch *backend.RevisionMismatchError
		incomplete       *backend.IncompleteOperationError
		alreadyActive    *backend.InstanceAlreadyActiveError
		notActive        *backend.InstanceNotActiveError
		reasonTooLong    *backend.ReasonTooLongError
	)
	switch {
	case errors.As(err, &secretNotFound), errors.As(err, &instanceNotFound):
		return http.StatusNotFound
	case errors.As(err, &revisionMismatch), errors.As(err, &incomplete),
		errors.As(err, &alreadyActive), errors.As(err, &notActive):
		return http.StatusConflict
	case errors.As(err, &reasonTooLong):
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// readBody decodes a JSON request body. The request must say it is JSON.
func readBody(r *http.Request, v any) error {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return NewErrorResponse(http.StatusUnsupportedMediaType, fmt.Errorf("request body must be application/json"))
	}
	bytes, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(bytes, v)
	}
	if err != nil {
		return NewErrorResponse(http.StatusBadRequest, err)
	}
	return nil
}
