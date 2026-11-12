package auth

import "fmt"

type Identity struct {
	Principal Principal
	Roles     Roles
}

// AssertPermission reports an error unless one held role grants every subject in permissions.
// An empty secretID matches a global grant or a grant on any secret.
func (id Identity) AssertPermission(permissions Permissions, secretID string) error {
	if id.CheckPermission(permissions, secretID) {
		return nil
	}
	names := make([]RoleName, len(id.Roles))
	for i, role := range id.Roles {
		names[i] = role.Name
	}
	return fmt.Errorf("operation not permitted with roles %v", names)
}

// CheckPermission reports whether one held role grants every subject in permissions.
// The role's own permissions apply to every secret. A per-secret map applies to that secret.
// An empty secretID matches when any of those grants does.
func (id Identity) CheckPermission(permissions Permissions, secretID string) bool {
	for _, role := range id.Roles {
		if role.allows(permissions, secretID) {
			return true
		}
		if secretID != "" {
			continue
		}
		for secret := range role.Secrets {
			if role.allows(permissions, secret) {
				return true
			}
		}
	}
	return false
}
