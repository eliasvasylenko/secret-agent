//go:build linux

package auth

import (
	"fmt"
	"maps"
	"net"
	"net/http"
	"os/user"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// PlatformClaims are the platform-specific claims that are obtained from unix socket peercreds
type PlatformClaims struct {
	Users  map[Entity]ClaimedRoles `json:"users,omitempty"`
	Groups map[Entity]ClaimedRoles `json:"groups,omitempty"`
}

// getClaimedRolesFromMap returns the union of ClaimedRoles for all entities in m
// that match (id, name).
func addClaimedRoles(authorisedRoles map[RoleName]struct{}, claims map[Entity]ClaimedRoles, id string, name string) {
	for entity, roles := range claims {
		if entity.matches(id, name) {
			for _, role := range roles {
				authorisedRoles[role] = struct{}{}
			}
		}
	}
}

// Claim the identity of the caller from the socket connection.
func (c *PlatformClaims) ClaimIdentity(request *http.Request, connection net.Conn) (*Identity, error) {
	user, groups, err := c.authenticate(connection)
	if err != nil {
		return nil, err
	}
	principal, roles := c.authorise(user, groups)
	return &Identity{Principal: principal, Roles: roles}, nil
}

// Authorise resolves the principal and roles for the authenticated user and groups from the claims config.
func (c *PlatformClaims) authorise(user *user.User, groups []*user.Group) (string, ClaimedRoles) {
	authorisedRoles := make(map[RoleName]struct{})
	if c.Users != nil {
		addClaimedRoles(authorisedRoles, c.Users, user.Uid, user.Username)
	}
	if c.Groups != nil {
		for _, group := range groups {
			addClaimedRoles(authorisedRoles, c.Groups, group.Gid, group.Name)
		}
	}

	principal := fmt.Sprintf("linux:%s/%s", user.Username, user.Uid)
	roles := slices.Collect(maps.Keys(authorisedRoles))

	return principal, roles
}

// Authenticate establishes the caller's user and groups from the socket peer credentials.
func (c *PlatformClaims) authenticate(connection net.Conn) (*user.User, []*user.Group, error) {
	var cred *unix.Ucred

	// Get Raw socket connection
	uc, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected socket type")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("error opening raw connection: %w", err)
	}

	// Get socket credentials
	controlErr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get socket credentials: %w", err)
	} else if controlErr != nil {
		return nil, nil, fmt.Errorf("failed to control socket: %w", controlErr)
	}

	// Lookup authenticated user
	authenticatedUser, err := user.LookupId(strconv.FormatUint(uint64(cred.Uid), 10))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup credential user: %w", err)
	}

	authenticatedGroup, err := user.LookupGroupId(strconv.FormatUint(uint64(cred.Gid), 10))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup credential group: %w", err)
	}

	authenticatedGroups := []*user.Group{authenticatedGroup}
	gids, err := authenticatedUser.GroupIds()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find user groups: %w", err)
	}
	for _, gid := range gids {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to lookup user group: %w", err)
		}
		authenticatedGroups = append(authenticatedGroups, group)
	}

	return authenticatedUser, authenticatedGroups, nil
}
