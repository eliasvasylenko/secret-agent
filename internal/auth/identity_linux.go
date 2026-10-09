//go:build linux

package auth

import (
	"fmt"
	"net"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

// authenticatePeer reads the socket peer from SO_PEERCRED. The username and
// groups come from the user database. The uid is what later matchers compare.
func authenticatePeer(connection net.Conn) (linuxPrincipal, error) {
	var cred *unix.Ucred

	uc, ok := connection.(*net.UnixConn)
	if !ok {
		return linuxPrincipal{}, fmt.Errorf("unexpected socket type")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return linuxPrincipal{}, fmt.Errorf("error opening raw connection: %w", err)
	}

	controlErr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	})
	if err != nil {
		return linuxPrincipal{}, fmt.Errorf("failed to get socket credentials: %w", err)
	} else if controlErr != nil {
		return linuxPrincipal{}, fmt.Errorf("failed to control socket: %w", controlErr)
	}

	authenticatedUser, err := user.LookupId(strconv.FormatUint(uint64(cred.Uid), 10))
	if err != nil {
		return linuxPrincipal{}, fmt.Errorf("failed to lookup credential user: %w", err)
	}

	groups, err := groupsOf(authenticatedUser)
	if err != nil {
		return linuxPrincipal{}, err
	}
	groups, err = withPeerGid(groups, cred.Gid)
	if err != nil {
		return linuxPrincipal{}, err
	}
	return linuxPrincipal{user: authenticatedUser, groups: groups}, nil
}

func withPeerGid(groups []*user.Group, peerGid uint32) ([]*user.Group, error) {
	gid := strconv.FormatUint(uint64(peerGid), 10)
	for _, g := range groups {
		if g.Gid == gid {
			return groups, nil
		}
	}
	g, err := user.LookupGroupId(gid)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup peer group: %w", err)
	}
	return append([]*user.Group{g}, groups...), nil
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
