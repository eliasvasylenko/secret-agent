//go:build linux

package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/user"
	"path/filepath"
	"testing"
)

func slicesEqual(a, b RoleNames) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

func TestPlatformBindingsUnmarshalMarshal(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "users and groups by id and name",
			json: `{"users":{"1000":["admin"],"alice":["reader"],"1001/bob":["writer"]},"groups":{"100":["admin"],"users":["reader"]}}`,
		},
		{
			name: "users only",
			json: `{"users":{"root":"admin"}}`,
		},
		{
			name: "groups only",
			json: `{"groups":{"secret-agent":["admin","reader"]}}`,
		},
		{
			name: "empty",
			json: `{}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var c PlatformBindings
			if err := json.Unmarshal([]byte(tc.json), &c); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			roundTrip, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var c2 PlatformBindings
			if err := json.Unmarshal(roundTrip, &c2); err != nil {
				t.Fatalf("Unmarshal(roundTrip): %v", err)
			}
			// Compare decoded structs (map key order is undefined)
			if len(c.Users) != len(c2.Users) {
				t.Errorf("Users length: got %d, want %d", len(c2.Users), len(c.Users))
			}
			for entity, roles := range c.Users {
				r2, ok := c2.Users[entity]
				if !ok {
					t.Errorf("Users: missing entity %+v", entity)
					continue
				}
				if !slicesEqual(roles, r2) {
					t.Errorf("Users[%+v]: got %v, want %v", entity, r2, roles)
				}
			}
			if len(c.Groups) != len(c2.Groups) {
				t.Errorf("Groups length: got %d, want %d", len(c2.Groups), len(c.Groups))
			}
			for entity, roles := range c.Groups {
				r2, ok := c2.Groups[entity]
				if !ok {
					t.Errorf("Groups: missing entity %+v", entity)
					continue
				}
				if !slicesEqual(roles, r2) {
					t.Errorf("Groups[%+v]: got %v, want %v", entity, r2, roles)
				}
			}
		})
	}
}

func TestAuthorise(t *testing.T) {
	alice := &user.User{Uid: "1000", Gid: "1000", Username: "alice", Name: "Alice", HomeDir: "/home/alice"}
	usersGroup := &user.Group{Gid: "100", Name: "users"}

	tests := []struct {
		name          string
		bindings      PlatformBindings
		user          *user.User
		groups        []*user.Group
		wantPrincipal string
		wantRoles     RoleNames
	}{
		{
			name:          "empty bindings yields principal only",
			bindings:      PlatformBindings{},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     nil,
		},
		{
			name: "user matched by uid",
			bindings: PlatformBindings{
				Users: map[Entity]RoleNames{
					{Id: "1000", Name: ""}: {"admin"},
				},
			},
			user:          alice,
			groups:        nil,
			wantPrincipal: "linux:alice/1000",
			wantRoles:     RoleNames{"admin"},
		},
		{
			name: "user matched by username",
			bindings: PlatformBindings{
				Users: map[Entity]RoleNames{
					{Id: "", Name: "alice"}: {"reader"},
				},
			},
			user:          alice,
			groups:        nil,
			wantPrincipal: "linux:alice/1000",
			wantRoles:     RoleNames{"reader"},
		},
		{
			name: "user matched by id/name",
			bindings: PlatformBindings{
				Users: map[Entity]RoleNames{
					{Id: "1000", Name: "alice"}: {"writer"},
				},
			},
			user:          alice,
			groups:        nil,
			wantPrincipal: "linux:alice/1000",
			wantRoles:     RoleNames{"writer"},
		},
		{
			name: "group matched by gid",
			bindings: PlatformBindings{
				Groups: map[Entity]RoleNames{
					{Id: "100", Name: ""}: {"reader"},
				},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     RoleNames{"reader"},
		},
		{
			name: "group matched by name",
			bindings: PlatformBindings{
				Groups: map[Entity]RoleNames{
					{Id: "", Name: "users"}: {"reader"},
				},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     RoleNames{"reader"},
		},
		{
			name: "user and group roles merged and deduplicated",
			bindings: PlatformBindings{
				Users: map[Entity]RoleNames{
					{Id: "1000", Name: ""}: {"admin", "reader"},
				},
				Groups: map[Entity]RoleNames{
					{Id: "100", Name: ""}: {"reader", "writer"},
				},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     RoleNames{"admin", "reader", "writer"},
		},
		{
			name: "no matching entity yields empty roles",
			bindings: PlatformBindings{
				Users:  map[Entity]RoleNames{{Id: "9999", Name: ""}: {"admin"}},
				Groups: map[Entity]RoleNames{{Id: "9999", Name: ""}: {"admin"}},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			principal, roles := tc.bindings.authorise(tc.user, tc.groups)
			if principal != tc.wantPrincipal {
				t.Errorf("principal: got %q, want %q", principal, tc.wantPrincipal)
			}
			if !roleNamesSetEqual(roles, tc.wantRoles) {
				t.Errorf("roles: got %v, want %v", roles, tc.wantRoles)
			}
		})
	}
}

func TestIdentify_nonUnixConn_returnsError(t *testing.T) {
	c := &Bindings{}
	_, conn := net.Pipe()
	defer conn.Close()

	_, err := c.Identify(&http.Request{}, conn)
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
		got, err := (&Bindings{
			PlatformBindings: PlatformBindings{
				Users: map[Entity]RoleNames{{Name: self.Username}: {"admin"}},
			},
		}).Identify(&http.Request{}, conn)
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

	t.Run("header ignored without forward-auth config", func(t *testing.T) {
		conn := unixPeer(t)
		req := &http.Request{Header: http.Header{DefaultForwardAuthHeader: []string{"root"}}}
		got, err := (&Bindings{}).Identify(req, conn)
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
