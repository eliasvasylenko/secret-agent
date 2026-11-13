package backend

import (
	"fmt"

	"github.com/eliasvasylenko/secret-agent/internal/secrets"
)

// Catalog and Runner refusals. Every implementation returns these types; the
// HTTP layer maps each one. Unknown errors are server failures.

type SecretNotFoundError struct{ SecretId string }

func (e *SecretNotFoundError) Error() string {
	return fmt.Sprintf("Secret plan does not exist %s", e.SecretId)
}

type InstanceNotFoundError struct{ InstanceId string }

func (e *InstanceNotFoundError) Error() string {
	return fmt.Sprintf("no such instance %s", e.InstanceId)
}

type RevisionMismatchError struct {
	Operation secrets.OperationName
	Revision  int
	Expected  int
}

func (e *RevisionMismatchError) Error() string {
	return fmt.Sprintf("cannot %s when revision %d does not match expected %d", e.Operation, e.Revision, e.Expected)
}

type IncompleteOperationError struct {
	Operation secrets.OperationName
	Previous  secrets.OperationName
}

func (e *IncompleteOperationError) Error() string {
	return fmt.Sprintf("cannot %s when previous %s has not succeeded", e.Operation, e.Previous)
}

type InstanceAlreadyActiveError struct {
	Operation secrets.OperationName
	ActiveId  string
}

func (e *InstanceAlreadyActiveError) Error() string {
	return fmt.Sprintf("cannot %s when instance %s is active", e.Operation, e.ActiveId)
}

type InstanceNotActiveError struct {
	Operation secrets.OperationName
}

func (e *InstanceNotActiveError) Error() string {
	return fmt.Sprintf("cannot %s when instance is not active", e.Operation)
}

type ReasonTooLongError struct {
	Length int
	Max    int
}

func (e *ReasonTooLongError) Error() string {
	return fmt.Sprintf("reason too long (%d exceeds max of %d bytes)", e.Length, e.Max)
}
