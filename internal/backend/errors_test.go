package backend

import (
	"errors"
	"fmt"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{&SecretNotFoundError{SecretId: "s1"}, "Secret plan does not exist s1"},
		{&InstanceNotFoundError{InstanceId: "i1"}, "no such instance i1"},
		{&RevisionMismatchError{Operation: secrets.Activate, Revision: 3, Expected: 1}, "cannot activate when revision 3 does not match expected 1"},
		{&IncompleteOperationError{Operation: secrets.Activate, Previous: secrets.Create}, "cannot activate when previous create has not succeeded"},
		{&InstanceAlreadyActiveError{Operation: secrets.Activate, ActiveId: "i1"}, "cannot activate when instance i1 is active"},
		{&InstanceNotActiveError{Operation: secrets.Deactivate}, "cannot deactivate when instance is not active"},
		{&ReasonTooLongError{Length: 10, Max: 8}, "reason too long (10 exceeds max of 8 bytes)"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("%T.Error() = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestErrorTypesDoNotCrossMatch(t *testing.T) {
	err := &InstanceAlreadyActiveError{Operation: secrets.Activate, ActiveId: "i1"}
	var already *InstanceAlreadyActiveError
	if !errors.As(err, &already) {
		t.Fatal("want InstanceAlreadyActiveError")
	}
	var mismatch *RevisionMismatchError
	if errors.As(err, &mismatch) {
		t.Fatal("InstanceAlreadyActiveError matched RevisionMismatchError")
	}
	wrapped := fmt.Errorf("run: %w", err)
	if !errors.As(wrapped, &already) {
		t.Fatal("wrapped error lost its type")
	}
}
