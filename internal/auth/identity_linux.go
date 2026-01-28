//go:build linux

package auth

import (
	"fmt"
	"net"
	"net/http"

	"golang.org/x/sys/unix"
)

type PlatformClaims struct {
	Users  map[string]ClaimedRoles `json:"users,omitempty"`
	Groups map[string]ClaimedRoles `json:"groups,omitempty"`
}

func (c *PlatformClaims) ClaimIdentity(request *http.Request, connection net.Conn) (*Identity, error) {
	var cred *unix.Ucred

	uc, ok := connection.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("unexpected socket type")
	}

	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("error opening raw connection: %s", err)
	}

	controlErr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd),
			unix.SOL_SOCKET,
			unix.SO_PEERCRED,
		)
	})

	if err != nil {
		return nil, fmt.Errorf("GetsockoptUcred() error: %s", err)
	}

	if controlErr != nil {
		return nil, fmt.Errorf("Control() error: %s", controlErr)
	}

	fmt.Printf("PlatformClaims: %v\n", *cred) // TODO debug log

	// TODO: Implementation incomplete - currently returns hardcoded "admin" role
	// The correct implementation should:
	// 1. Look up the user by uid (cred.Uid) in c.Users map
	// 2. Look up the group by gid (cred.Gid) in c.Groups map
	// 3. Return the union of roles from both user and group mappings
	// 4. If neither user nor group is found, return empty ClaimedRoles (or error)
	// This allows the permissions system to map Unix users/groups to roles
	// without requiring root access for instance management operations.
	return &Identity{Principal: "admin", Roles: []RoleName{"admin"}}, nil
}
