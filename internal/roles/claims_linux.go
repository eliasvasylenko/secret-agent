//go:build linux

package roles

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

func (c *PlatformClaims) ClaimRoles(request *http.Request, connection net.Conn) (ClaimedRoles, error) {
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

	return ClaimedRoles{"admin"}, nil
}
