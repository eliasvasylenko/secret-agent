package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

func TestWriteError_mapsBackendErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
		msg  string
	}{
		{"secret missing", &backend.SecretNotFoundError{SecretId: "s1"}, http.StatusNotFound, "Secret plan does not exist s1"},
		{"instance missing", &backend.InstanceNotFoundError{InstanceId: "i1"}, http.StatusNotFound, "no such instance i1"},
		{"revision", &backend.RevisionMismatchError{Operation: secrets.Activate, Revision: 3, Expected: 1}, http.StatusConflict, "cannot activate when revision 3 does not match expected 1"},
		{"incomplete", &backend.IncompleteOperationError{Operation: secrets.Activate, Previous: secrets.Create}, http.StatusConflict, "cannot activate when previous create has not succeeded"},
		{"already active", &backend.InstanceAlreadyActiveError{Operation: secrets.Activate, ActiveId: "i1"}, http.StatusConflict, "cannot activate when instance i1 is active"},
		{"not active", &backend.InstanceNotActiveError{Operation: secrets.Deactivate}, http.StatusConflict, "cannot deactivate when instance is not active"},
		{"reason", &backend.ReasonTooLongError{Length: 10, Max: 8}, http.StatusBadRequest, "reason too long (10 exceeds max of 8 bytes)"},
		{"unclassified", fmt.Errorf("disk full"), http.StatusInternalServerError, "disk full"},
		{"http", NewErrorResponse(http.StatusForbidden, errors.New("operation not permitted")), http.StatusForbidden, "operation not permitted"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if err := writeError(rec, tt.err); err != nil {
				t.Fatal(err)
			}
			if rec.Code != tt.code {
				t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, tt.code, rec.Body.Bytes())
			}
			var got ErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if got.HttpError == nil || got.HttpError.Message != tt.msg {
				t.Errorf("message = %+v, want %q", got.HttpError, tt.msg)
			}
		})
	}
}
