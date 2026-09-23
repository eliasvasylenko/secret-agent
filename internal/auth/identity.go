//go:build linux

package auth

import (
	"net"
	"net/http"
)

type Identity struct {
	Principal string
	Roles     RoleNames
}

// Bindings map principals (users, groups, forward-auth hops) to role names.
type Bindings struct {
	PlatformBindings `json:""`
	ForwardAuth      *ForwardAuth `json:"forwardAuth,omitempty"`
}

// Identify authenticates the Unix peer, then authorises. If ForwardAuth trusts
// that peer, the end-user is the name header, not the hop.
func (b *Bindings) Identify(request *http.Request, connection net.Conn) (*Identity, error) {
	peer, groups, err := b.PlatformBindings.Authenticate(connection)
	if err != nil {
		return nil, err
	}
	if b.ForwardAuth.trusts(peer) {
		name, err := forwardAuthUser(request, b.ForwardAuth.headerName())
		if err != nil {
			return nil, err
		}
		return b.identityFromForwarded(name)
	}
	principal, roles := b.PlatformBindings.Authorise(peer, groups)
	return &Identity{Principal: principal, Roles: roles}, nil
}
