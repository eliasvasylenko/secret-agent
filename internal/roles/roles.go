package roles

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

// Roles keyed by name
type Roles map[RoleName]Role

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
	Everything Subject = "everything"
	Secrets    Subject = "secrets"
	Instances  Subject = "instances"
)

// Actions which can be performed upon subjects
type Action string

const (
	Anything Action = "anything"
	List     Action = "list"
	Read     Action = "read"
	Write    Action = "write"
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

func (r Roles) AssertPermission(claims ClaimedRoles, permissions Permissions) error {
	ok := r.CheckPermission(claims, permissions)
	if !ok {
		return fmt.Errorf("Permissions %v are not permitted with provided identity %v", permissions, claims)
	}

	return nil
}

func (r Roles) CheckPermission(claims ClaimedRoles, permissions Permissions) bool {
	for _, roleName := range claims {
		role := r[roleName]
		for subject, action := range permissions {
			permittedAction, ok := role.Permissions[subject]
			if !ok || permittedAction != action {
				continue
			}
		}
		return true
	}
	return false
}
