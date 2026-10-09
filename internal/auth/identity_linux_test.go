//go:build linux

package auth

import (
	"fmt"
	"net"
	"net/http"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func linuxBinding(b LinuxBinding) Binding {
	return Binding{Auth: systemAuthenticator, LinuxBinding: b}
}

func id(n uint32) *uint32 {
	return &n
}

func idString(s string) *uint32 {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		panic(err)
	}
	return id(uint32(n))
}

// roleNamesSetEqual compares roles as sets (order-independent).
func roleNamesSetEqual(a, b RoleNames) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[RoleName]struct{})
	for _, r := range a {
		seen[r] = struct{}{}
	}
	for _, r := range b {
		_, ok := seen[r]
		if !ok {
			return false
		}
	}
	return true
}

func TestMatchLinux(t *testing.T) {
	alice := &user.User{Uid: "1000", Gid: "1000", Username: "alice", Name: "Alice", HomeDir: "/home/alice"}
	usersGroup := &user.Group{Gid: "100", Name: "users"}
	orig := lookupUser
	lookupUser = func(name string) (*user.User, error) {
		if name == "alice" {
			return alice, nil
		}
		return nil, fmt.Errorf("unknown user %s", name)
	}
	t.Cleanup(func() { lookupUser = orig })

	tests := []struct {
		name      string
		roles     Roles
		groups    []*user.Group
		wantRoles RoleNames
	}{
		{
			name:      "empty roles",
			roles:     Roles{},
			groups:    []*user.Group{usersGroup},
			wantRoles: nil,
		},
		{
			name:      "user matched by uid",
			roles:     Roles{"admin": {Bindings: []Binding{linuxBinding(LinuxBinding{UID: id(1000)})}}},
			wantRoles: RoleNames{"admin"},
		},
		{
			name:      "user matched by username",
			roles:     Roles{"reader": {Bindings: []Binding{linuxBinding(LinuxBinding{User: "alice"})}}},
			wantRoles: RoleNames{"reader"},
		},
		{
			name:      "user matched by uid and name",
			roles:     Roles{"writer": {Bindings: []Binding{linuxBinding(LinuxBinding{UID: id(1000), User: "alice"})}}},
			wantRoles: RoleNames{"writer"},
		},
		{
			name:      "uid and name disagree",
			roles:     Roles{"writer": {Bindings: []Binding{linuxBinding(LinuxBinding{UID: id(1001), User: "alice"})}}},
			wantRoles: nil,
		},
		{
			name:      "group matched by gid",
			roles:     Roles{"reader": {Bindings: []Binding{linuxBinding(LinuxBinding{GID: id(100)})}}},
			groups:    []*user.Group{usersGroup},
			wantRoles: RoleNames{"reader"},
		},
		{
			name:      "group matched by name",
			roles:     Roles{"reader": {Bindings: []Binding{linuxBinding(LinuxBinding{Group: "users"})}}},
			groups:    []*user.Group{usersGroup},
			wantRoles: RoleNames{"reader"},
		},
		{
			name: "user and group roles are both kept",
			roles: Roles{
				"admin":  {Bindings: []Binding{linuxBinding(LinuxBinding{UID: id(1000)})}},
				"reader": {Bindings: []Binding{linuxBinding(LinuxBinding{GID: id(100)})}},
				"writer": {Bindings: []Binding{linuxBinding(LinuxBinding{GID: id(100)})}},
			},
			groups:    []*user.Group{usersGroup},
			wantRoles: RoleNames{"admin", "reader", "writer"},
		},
		{
			name: "no match",
			roles: Roles{
				"admin": {Bindings: []Binding{linuxBinding(LinuxBinding{UID: id(9999)}), linuxBinding(LinuxBinding{GID: id(9999)})}},
			},
			groups:    []*user.Group{usersGroup},
			wantRoles: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			roles := tc.roles.matchSystem(platformPeer{user: alice, groups: tc.groups})
			if !roleNamesSetEqual(roles, tc.wantRoles) {
				t.Errorf("roles: got %v, want %v", roles, tc.wantRoles)
			}
		})
	}
}

func TestIdentify_nonUnixConn_returnsError(t *testing.T) {
	_, conn := net.Pipe()
	defer conn.Close()

	_, err := (Policy{}).Identify(&http.Request{}, conn)
	if err == nil {
		t.Error("expected error for non-UnixConn")
	}
	if err != nil && err.Error() != "unexpected socket type" {
		t.Errorf("expected 'unexpected socket type', got %v", err)
	}
}

func TestIdentify_unixPeercreds(t *testing.T) {
	self, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	wantPrincipal := fmt.Sprintf("linux:%s/%s", self.Username, self.Uid)

	t.Run("direct peer is the caller", func(t *testing.T) {
		conn := unixPeer(t)
		got, err := (Policy{Roles: Roles{"admin": {Bindings: []Binding{linuxBinding(LinuxBinding{User: self.Username})}}}}).Identify(&http.Request{}, conn)
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal != wantPrincipal {
			t.Errorf("principal: got %q, want %q", got.Principal, wantPrincipal)
		}
		if !roleNamesSetEqual(got.Roles, RoleNames{"admin"}) {
			t.Errorf("roles: got %v, want [admin]", got.Roles)
		}
	})

	t.Run("header ignored when the peer is not an asserter", func(t *testing.T) {
		conn := unixPeer(t)
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"root"}}}
		got, err := (Policy{}).Identify(req, conn)
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal != wantPrincipal {
			t.Errorf("principal: got %q, want %q (header must not impersonate)", got.Principal, wantPrincipal)
		}
	})
}

func unixPeer(t *testing.T) net.Conn {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	errc := make(chan error, 1)
	peer := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		peer <- conn
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	select {
	case err := <-errc:
		t.Fatal(err)
		return nil
	case conn := <-peer:
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
}
