//go:build linux

package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/user"
	"strconv"
)

func init() {
	var prototype Authenticator[linuxPrincipal] = linuxAuthenticator{}
	RegisterAuthenticatorPrototype(linuxKind, &prototype)
}

// linuxPrincipal is the socket credential.
type linuxPrincipal struct {
	user   *user.User
	groups []*user.Group
}

func (p linuxPrincipal) GetName() string {
	return fmt.Sprintf("linux:%s/%s", p.user.Username, p.user.Uid)
}

// linuxAuthenticator is the reserved system authenticator. Kind is linux.
type linuxAuthenticator struct{}

func (linuxAuthenticator) Authenticate(_ *http.Request, connection net.Conn) (linuxPrincipal, error) {
	return authenticatePeer(connection)
}

func (linuxAuthenticator) NewBinding() Binding[linuxPrincipal] {
	return &linuxBinding{}
}

func (linuxAuthenticator) UnmarshalJSON(data []byte) error {
	var raw struct {
		Name string `json:"name"`
	}
	if raw.Name != systemAuthenticator {
		return fmt.Errorf("linux authenticator name must be %q", systemAuthenticator)
	}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}
	return nil
}

// linuxBinding matches the socket credential's user or its group.
// The user arm is uid and/or user. The group arm is gid and/or group.
// One arm must be set. Both fields of that arm must match.
type linuxBinding struct {
	UID   *uint32 `json:"uid,omitempty"`
	User  string  `json:"user,omitempty"`
	GID   *uint32 `json:"gid,omitempty"`
	Group string  `json:"group,omitempty"`
}

func systemBinding(b linuxBinding) Binding[Principal] {
	return AnyBinding[linuxPrincipal]{binding: &b}
}

func (b *linuxBinding) UnmarshalJSON(data []byte) error {
	type plain linuxBinding
	var raw plain
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}
	*b = linuxBinding(raw)
	return b.validate()
}

func (b linuxBinding) Bind(principal linuxPrincipal) (bool, error) {
	err := b.validate()
	if err != nil {
		return false, err
	}
	if b.userArm() {
		return b.matchUser(principal.user), nil
	}
	return b.matchGroup(principal.groups)
}

func (b linuxBinding) validate() error {
	switch {
	case b.userArm() && b.groupArm():
		return fmt.Errorf("linux binding must not set both a user and a group")
	case !b.userArm() && !b.groupArm():
		return fmt.Errorf("linux binding must set a user (uid and/or user) or a group (gid and/or group)")
	default:
		return nil
	}
}

func (b linuxBinding) userArm() bool {
	return b.UID != nil || b.User != ""
}

func (b linuxBinding) groupArm() bool {
	return b.GID != nil || b.Group != ""
}

func (b linuxBinding) matchUser(peer *user.User) bool {
	if b.User != "" && b.User != peer.Username {
		return false
	}
	if b.UID != nil && !idEquals(*b.UID, peer.Uid) {
		return false
	}
	return true
}

func (b linuxBinding) matchGroup(groups []*user.Group) (bool, error) {
	for _, group := range groups {
		if b.Group != "" && group.Name != b.Group {
			continue
		}
		if b.GID != nil && !idEquals(*b.GID, group.Gid) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func idEquals(id uint32, decimal string) bool {
	return strconv.FormatUint(uint64(id), 10) == decimal
}
