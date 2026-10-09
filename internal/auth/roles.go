package auth

import (
	"encoding/json"
	"errors"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

// Roles keyed by name
type Roles map[RoleName]Role

// RoleName is a name for a role.
type RoleName string

// RoleNames is a list of role names. JSON may be a single string or an array.
type RoleNames []RoleName

func (r *RoleNames) UnmarshalJSON(p []byte) error {
	var one RoleName
	err1 := json.Unmarshal(p, &one)
	if err1 == nil {
		*r = RoleNames{one}
		return nil
	}
	var many []RoleName
	err2 := json.Unmarshal(p, &many)
	if err2 != nil {
		return errors.Join(err1, err2)
	}
	*r = many
	return nil
}

func (r RoleNames) MarshalJSON() ([]byte, error) {
	if len(r) == 1 {
		return marshal.JSON(r[0])
	}
	return marshal.JSON([]RoleName(r))
}

// A role and its permissions.
// Name is the key in the roles object, not a field of it.
// Bindings are who holds this role. Each names an authenticator.
// Permissions apply to every secret.
// Secrets grants a permission set on one secret.
type Role struct {
	Name        RoleName               `json:"-"`
	Bindings    Bindings               `json:"bindings,omitempty"`
	Permissions Permissions            `json:"permissions"`
	Secrets     map[string]Permissions `json:"secrets,omitempty"`
}
