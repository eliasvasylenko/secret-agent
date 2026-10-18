package auth

import (
	"fmt"
)

// Roles is the ordered role catalog.
type Roles []*Role

// RoleName is a name for a role.
type RoleName string

// A role and its permissions.
// Bindings are who holds this role. Each names an authenticator.
// Permissions apply to every secret.
// Secrets grants a permission set on one secret.
type Role struct {
	Name        RoleName               `json:"name"`
	Bindings    Bindings               `json:"bindings,omitempty"`
	Permissions Permissions            `json:"permissions"`
	Secrets     map[string]Permissions `json:"secrets,omitempty"`
}

func newRoles(roles []*Role) (Roles, error) {
	seen := make(map[RoleName]struct{}, len(roles))
	for _, role := range roles {
		if role.Name == "" {
			return nil, fmt.Errorf("role name must not be empty")
		}
		if _, ok := seen[role.Name]; ok {
			return nil, fmt.Errorf("duplicate role %q", role.Name)
		}
		seen[role.Name] = struct{}{}
	}
	return roles, nil
}

func (role *Role) allows(permissions Permissions, secretID string) bool {
	for subject, action := range permissions {
		if !role.Permissions.matches(subject, action) && !role.Secrets[secretID].matches(subject, action) {
			return false
		}
	}
	return true
}

func (r Roles) BoundRoles(principal Principal) (Roles, error) {
	var matched Roles
	for _, role := range r {
		for _, binding := range role.Bindings {
			ok, err := binding.Bind(principal.credential)
			if err != nil {
				return nil, err
			}
			if ok {
				matched = append(matched, role)
				break
			}
		}
	}
	return matched, nil
}
