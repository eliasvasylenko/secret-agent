//go:build linux

package auth

import (
	"fmt"
	"net/http"
	"os/user"
	"strings"
	"unicode"
)

// DefaultForwardAuthHeader is used when ForwardAuth.Header is empty.
const DefaultForwardAuthHeader = "X-Secret-Agent-User"

// lookupUser is user.Lookup; tests may replace it.
var lookupUser = user.Lookup

// ForwardAuth names Unix peers allowed to assert an end-user via an HTTP header.
// Hop trust is peercreds: the header is ignored unless SO_PEERCRED matches Peers
// (an allowlist of last hops, not a chain).
type ForwardAuth struct {
	Peers  []Entity `json:"peers,omitempty"`
	Header string   `json:"header,omitempty"`
}

func (f *ForwardAuth) headerName() string {
	if f != nil && f.Header != "" {
		return f.Header
	}
	return DefaultForwardAuthHeader
}

func (f *ForwardAuth) trusts(peer *user.User) bool {
	if f == nil {
		return false
	}
	for _, entity := range f.Peers {
		if entity.Id == "" && entity.Name == "" {
			continue
		}
		if entity.matches(peer.Uid, peer.Username) {
			return true
		}
	}
	return false
}

func forwardAuthUser(request *http.Request, header string) (string, error) {
	if request == nil {
		return "", fmt.Errorf("forward-auth header %q required", header)
	}
	values := request.Header.Values(header)
	if len(values) != 1 {
		return "", fmt.Errorf("forward-auth header %q required", header)
	}
	name := strings.TrimSpace(values[0])
	if name == "" || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("forward-auth header %q required", header)
	}
	return name, nil
}

func (b *Bindings) identityFromForwarded(name string) (*Identity, error) {
	u, err := lookupUser(name)
	if err != nil {
		dummy := &user.User{Username: name}
		_, roles := b.Authorise(dummy, nil)
		return &Identity{Principal: "http:" + name, Roles: roles}, nil
	}
	groups, err := groupsOf(u)
	if err != nil {
		return nil, err
	}
	principal, roles := b.Authorise(u, groups)
	return &Identity{Principal: principal, Roles: roles}, nil
}
