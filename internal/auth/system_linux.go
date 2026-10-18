//go:build linux

package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

var systemAuthenticator Authenticator[Principal] = AnyAuthenticator[linuxPrincipal]{authenticator: linuxAuthenticator{}}

const linuxKind = "linux"

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

func (linuxAuthenticator) unmarshal(data []byte, existing Authenticators) error {
	return json.Unmarshal(data, &struct{}{})
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
