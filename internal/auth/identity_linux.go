//go:build linux

package auth

import (
	"fmt"
	"maps"
	"net"
	"os/user"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"
)

// PlatformBindings map local users and groups to roles. This is the Linux
// implementation: identity of the socket peer comes from SO_PEERCRED, not the
// HTTP request. Other platforms would define the same type differently.
type PlatformBindings struct {
	Users  map[Entity]RoleNames `json:"users,omitempty"`
	Groups map[Entity]RoleNames `json:"groups,omitempty"`
}

func addRoleNames(bound map[RoleName]struct{}, bindings map[Entity]RoleNames, id string, name string) {
	for entity, roles := range bindings {
		if entity.matches(id, name) {
			for _, role := range roles {
				bound[role] = struct{}{}
			}
		}
	}
}

func (b *PlatformBindings) Authorise(u *user.User, groups []*user.Group) (string, RoleNames) {
	bound := make(map[RoleName]struct{})
	if b.Users != nil {
		addRoleNames(bound, b.Users, u.Uid, u.Username)
	}
	if b.Groups != nil {
		for _, group := range groups {
			addRoleNames(bound, b.Groups, group.Gid, group.Name)
		}
	}

	principal := fmt.Sprintf("linux:%s/%s", u.Username, u.Uid)
	roles := slices.Collect(maps.Keys(bound))

	return principal, roles
}

func (b *PlatformBindings) Authenticate(connection net.Conn) (*user.User, []*user.Group, error) {
	var cred *unix.Ucred

	uc, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected socket type")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("error opening raw connection: %w", err)
	}

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

	authenticatedUser, err := user.LookupId(strconv.FormatUint(uint64(cred.Uid), 10))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to lookup credential user: %w", err)
	}

	groups, err := groupsOf(authenticatedUser)
	if err != nil {
		return nil, nil, err
	}
	return authenticatedUser, groups, nil
}

func groupsOf(u *user.User) ([]*user.Group, error) {
	var groups []*user.Group
	if u.Gid != "" {
		authenticatedGroup, err := user.LookupGroupId(u.Gid)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup credential group: %w", err)
		}
		groups = append(groups, authenticatedGroup)
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("failed to find user groups: %w", err)
	}
	for _, gid := range gids {
		group, err := user.LookupGroupId(gid)
		if err != nil {
			return nil, fmt.Errorf("failed to lookup user group: %w", err)
		}
		groups = append(groups, group)
	}
	return groups, nil
}
