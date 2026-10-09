//go:build linux

package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func role(name RoleName, bindings ...Binding[Principal]) *Role {
	return &Role{Name: name, Bindings: bindings}
}

func roleNamed(roles Roles, name RoleName) *Role {
	for _, role := range roles {
		if role.Name == name {
			return role
		}
	}
	return nil
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

func sameRoleNames(roles Roles, want []RoleName) bool {
	if len(roles) != len(want) {
		return false
	}
	seen := make(map[RoleName]struct{}, len(roles))
	for _, role := range roles {
		seen[role.Name] = struct{}{}
	}
	for _, name := range want {
		if _, ok := seen[name]; !ok {
			return false
		}
	}
	return true
}

func TestMatchLinux(t *testing.T) {
	alice := &user.User{Uid: "1000", Gid: "1000", Username: "alice", Name: "Alice", HomeDir: "/home/alice"}
	usersGroup := &user.Group{Gid: "100", Name: "users"}

	tests := []struct {
		name      string
		roles     Roles
		groups    []*user.Group
		wantRoles []RoleName
	}{
		{
			name:      "empty roles",
			roles:     Roles{},
			groups:    []*user.Group{usersGroup},
			wantRoles: nil,
		},
		{
			name:      "user matched by uid",
			roles:     Roles{role("admin", systemBinding(linuxBinding{UID: id(1000)}))},
			wantRoles: []RoleName{"admin"},
		},
		{
			name:      "user matched by username",
			roles:     Roles{role("reader", systemBinding(linuxBinding{User: "alice"}))},
			wantRoles: []RoleName{"reader"},
		},
		{
			name:      "user matched by uid and name",
			roles:     Roles{role("writer", systemBinding(linuxBinding{UID: id(1000), User: "alice"}))},
			wantRoles: []RoleName{"writer"},
		},
		{
			name:      "uid and name disagree",
			roles:     Roles{role("writer", systemBinding(linuxBinding{UID: id(1001), User: "alice"}))},
			wantRoles: nil,
		},
		{
			name:      "group matched by gid",
			roles:     Roles{role("reader", systemBinding(linuxBinding{GID: id(100)}))},
			groups:    []*user.Group{usersGroup},
			wantRoles: []RoleName{"reader"},
		},
		{
			name:      "group matched by name",
			roles:     Roles{role("reader", systemBinding(linuxBinding{Group: "users"}))},
			groups:    []*user.Group{usersGroup},
			wantRoles: []RoleName{"reader"},
		},
		{
			name: "user and group roles are both kept",
			roles: Roles{
				role("admin", systemBinding(linuxBinding{UID: id(1000)})),
				role("reader", systemBinding(linuxBinding{GID: id(100)})),
				role("writer", systemBinding(linuxBinding{GID: id(100)})),
			},
			groups:    []*user.Group{usersGroup},
			wantRoles: []RoleName{"admin", "reader", "writer"},
		},
		{
			name: "no match",
			roles: Roles{
				role("admin", systemBinding(linuxBinding{UID: id(9999)}), systemBinding(linuxBinding{GID: id(9999)})),
			},
			groups:    []*user.Group{usersGroup},
			wantRoles: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			roles, err := tc.roles.BoundRoles(linuxPrincipal{user: alice, groups: tc.groups})
			if err != nil {
				t.Fatal(err)
			}
			if !sameRoleNames(roles, tc.wantRoles) {
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
		got, err := (Policy{Roles: Roles{role("admin", systemBinding(linuxBinding{User: self.Username}))}}).Identify(&http.Request{}, conn)
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != wantPrincipal {
			t.Errorf("principal: got %q, want %q", got.Principal.GetName(), wantPrincipal)
		}
		if !sameRoleNames(got.Roles, []RoleName{"admin"}) {
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
		if got.Principal.GetName() != wantPrincipal {
			t.Errorf("principal: got %q, want %q (header must not impersonate)", got.Principal.GetName(), wantPrincipal)
		}
	})
}

func TestPolicy_systemBinding(t *testing.T) {
	var policy Policy
	err := json.Unmarshal([]byte(`{
		"roles": [
			{
				"name": "admin",
				"bindings": [
					{"auth": "system", "uid": 0},
					{"auth": "system", "group": "secret-agent"}
				]
			}
		]
	}`), &policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := policy.Authenticators[systemAuthenticator]; !ok {
		t.Fatal("system authenticator missing")
	}
	admin := roleNamed(policy.Roles, "admin")
	if admin == nil || len(admin.Bindings) != 2 {
		t.Fatalf("admin bindings = %v", policy.Roles)
	}

	err = json.Unmarshal([]byte(`{"roles":[{"name":"admin","bindings":[{"auth":"system","uid":0,"group":"wheel"}]}]}`), &policy)
	if err == nil {
		t.Fatal("expected user and group arms to be rejected")
	}

	err = json.Unmarshal([]byte(`{"roles":[{"name":"admin"},{"name":"admin"}]}`), &policy)
	if err == nil {
		t.Fatal("expected duplicate role name to be rejected")
	}
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
