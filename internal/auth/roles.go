package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

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
// Secrets grants a permission set on one secret. Permissions still apply to every secret.
type Role struct {
	Name        RoleName               `json:"-"`
	Permissions Permissions            `json:"permissions"`
	Secrets     map[string]Permissions `json:"secrets,omitempty"`
}

// A set of permissions. A subject or action outside the known constants is rejected at load.
type Permissions map[Subject]Action

// Subjects which can be acted upon
type Subject string

const (
	// All subjects
	All Subject = "all"
	// Secrets subject
	Secrets Subject = "secrets"
	// Instances subject
	Instances Subject = "instances"
)

// Actions which can be performed upon subjects
type Action string

const (
	// Any action
	Any Action = "any"
	// List action
	List Action = "list"
	// Read action
	Read Action = "read"
	// Write action
	Write Action = "write"
)

func (p *Permissions) UnmarshalJSON(data []byte) error {
	var raw map[Subject]Action
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for subject, action := range raw {
		switch subject {
		case All, Secrets, Instances:
		default:
			return fmt.Errorf("invalid subject %q", subject)
		}
		switch action {
		case Any, List, Read, Write:
		default:
			return fmt.Errorf("invalid action %q", action)
		}
	}
	*p = raw
	return nil
}

func Load(rolesFileName string) (Roles, error) {
	rolesFile, err := os.Open(rolesFileName)
	if err != nil {
		return Roles{}, err
	}

	rolesBytes, err := io.ReadAll(rolesFile)
	if err != nil {
		return Roles{}, err
	}

	var roles Roles
	err = json.Unmarshal(rolesBytes, &roles)
	if err != nil {
		return Roles{}, err
	}

	return roles, nil
}

func (r *Roles) UnmarshalJSON(p []byte) error {
	parsed := make(map[RoleName]Role, 0)
	if err := json.Unmarshal(p, &parsed); err != nil {
		return err
	}
	*r = Roles{}
	for name, role := range parsed {
		if name == "" {
			return fmt.Errorf("Failed to parse role name")
		}
		role.Name = name
		(*r)[name] = role
	}
	return nil
}

func (r Roles) MarshalJSON() ([]byte, error) {
	docs := make(map[RoleName]Role, len(r))
	for _, role := range r {
		docs[role.Name] = role
	}
	return marshal.JSON(docs)
}

// AssertPermission checks if the bound roles include the given permissions.
func (r Roles) AssertPermission(bound RoleNames, permissions Permissions, secretID string) error {
	if r.CheckPermission(bound, permissions, secretID) {
		return nil
	}
	return fmt.Errorf("operation not permitted with roles %v", bound)
}

// CheckPermission reports whether one bound role grants every subject in permissions.
// The role's own permissions apply to every secret. A per-secret map applies to that secret.
// An empty secretID matches when any of those grants does.
func (r Roles) CheckPermission(bound RoleNames, permissions Permissions, secretID string) bool {
	for _, roleName := range bound {
		role := r[roleName]
		if role.allows(permissions, secretID) {
			return true
		}
		if secretID != "" {
			continue
		}
		for id := range role.Secrets {
			if role.allows(permissions, id) {
				return true
			}
		}
	}
	return false
}

func (role Role) allows(permissions Permissions, secretID string) bool {
	for subject, action := range permissions {
		if !role.Permissions.matches(subject, action) && !role.Secrets[secretID].matches(subject, action) {
			return false
		}
	}
	return true
}

func (p Permissions) matches(subject Subject, action Action) bool {
	if permitted, ok := p[subject]; ok && (permitted == action || permitted == Any) {
		return true
	}
	permitted, ok := p[All]
	return ok && (permitted == action || permitted == Any)
}
