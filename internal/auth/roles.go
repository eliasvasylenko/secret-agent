package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

// Roles keyed by name
type Roles map[RoleName]Role

// RoleName is a name for a role.
type RoleName string

// A role and its permissions
type Role struct {
	Name        RoleName    `json:"name"`
	Permissions Permissions `json:"permissions"`
}

// A set of permissions
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
	rolePermissions := make(map[RoleName]struct {
		Permissions `json:"permissions"`
	}, 0)
	if err := json.Unmarshal(p, &rolePermissions); err != nil {
		return err
	}
	*r = Roles{}
	for name, permissions := range rolePermissions {
		if name == "" {
			return fmt.Errorf("Failed to parse role name")
		}
		(*r)[name] = Role{
			Name:        name,
			Permissions: permissions.Permissions,
		}
	}
	return nil
}

func (r Roles) MarshalJSON() ([]byte, error) {
	rolePermissions := make(map[RoleName]struct {
		Permissions `json:"permissions"`
	}, 0)
	for _, role := range r {
		rolePermissions[role.Name] = struct {
			Permissions "json:\"permissions\""
		}{role.Permissions}
	}
	return marshal.JSON(rolePermissions)
}

// AssertPermission checks if the given claims have the given permissions.
func (r Roles) AssertPermission(claims ClaimedRoles, permissions Permissions) error {
	ok := r.CheckPermission(claims, permissions)
	if !ok {
		return fmt.Errorf("operation not permitted with claimed roles %v", claims)
	}

	return nil
}

// CheckPermission checks if the given claims have the given permissions.
func (r Roles) CheckPermission(claims ClaimedRoles, permissions Permissions) bool {
	for _, roleName := range claims {
		role := r[roleName]
		allPermitted := true
		for subject, action := range permissions {
			if !role.CheckPermission(subject, action) && !role.CheckPermission(All, action) {
				allPermitted = false
				break
			}
		}
		if allPermitted {
			return true
		}
	}
	return false
}

// CheckPermission checks if the given role has the given permission.
func (r Role) CheckPermission(subject Subject, action Action) bool {
	permittedAction, ok := r.Permissions[subject]
	return ok && (permittedAction == action || permittedAction == Any)
}
