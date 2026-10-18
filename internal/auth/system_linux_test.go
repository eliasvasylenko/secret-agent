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

func TestLinuxBinding(t *testing.T) {
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
			name:      "gid and name agree",
			roles:     Roles{role("reader", systemBinding(linuxBinding{GID: id(100), Group: "users"}))},
			groups:    []*user.Group{usersGroup},
			wantRoles: []RoleName{"reader"},
		},
		{
			name:      "gid and name disagree",
			roles:     Roles{role("reader", systemBinding(linuxBinding{GID: id(101), Group: "users"}))},
			groups:    []*user.Group{usersGroup},
			wantRoles: nil,
		},
		{
			name:      "group binding with no groups",
			roles:     Roles{role("reader", systemBinding(linuxBinding{Group: "users"}))},
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

func TestIdentify_system(t *testing.T) {
	t.Run("non unix connection", func(t *testing.T) {
		_, conn := net.Pipe()
		defer conn.Close()

		_, err := policyWith(t, nil).Identify(&http.Request{}, conn)
		if err == nil {
			t.Fatal("expected error for non-UnixConn")
		}
		if err.Error() != "unexpected socket type" {
			t.Errorf("expected 'unexpected socket type', got %v", err)
		}
	})

	self, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	wantPrincipal := fmt.Sprintf("linux:%s/%s", self.Username, self.Uid)

	t.Run("direct peer is the caller", func(t *testing.T) {
		got, err := policyWith(t, Roles{role("admin", systemBinding(linuxBinding{User: self.Username}))}).Identify(&http.Request{}, unixPeer(t))
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
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"root"}}}
		got, err := policyWith(t, nil).Identify(req, unixPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != wantPrincipal {
			t.Errorf("principal: got %q, want %q (header must not impersonate)", got.Principal.GetName(), wantPrincipal)
		}
	})

	t.Run("omitted auth is the system authenticator", func(t *testing.T) {
		gid, err := strconv.ParseUint(self.Gid, 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		policy := loadPolicy(t, fmt.Sprintf(`{"roles":[{"name":"readers","bindings":[{"gid":%d}]}]}`, gid))
		got, err := policy.Identify(&http.Request{}, unixPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != wantPrincipal {
			t.Errorf("principal: got %q, want %q", got.Principal.GetName(), wantPrincipal)
		}
		if !sameRoleNames(got.Roles, []RoleName{"readers"}) {
			t.Errorf("roles: got %v, want [readers]", got.Roles)
		}
	})
}

func TestIdentify_assert(t *testing.T) {
	self, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(self.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(n)
	socketName := fmt.Sprintf("linux:%s/%s", self.Username, self.Uid)

	t.Run("header ignored when the peer is not an asserter", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":"definitely-not-me"}}],
			"roles": [
				{"name":"admin","bindings":[{"auth":"system","uid":%d}]},
				{"name":"reader","bindings":[{"auth":"caddy","name":"john"}]}
			]
		}`, uid))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"john"}}}
		got, err := policy.Identify(req, unixPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != socketName {
			t.Errorf("principal: got %q, want %q", got.Principal.GetName(), socketName)
		}
		if !sameRoleNames(got.Roles, []RoleName{"admin"}) {
			t.Errorf("roles: got %v, want [admin]", got.Roles)
		}
	})

	t.Run("asserter requires its header", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":%q}}],
			"roles": [{"name":"reader","bindings":[{"auth":"caddy","name":"john"}]}]
		}`, self.Username))
		_, err := policy.Identify(&http.Request{}, unixPeer(t))
		if fmt.Sprint(err) != fmt.Sprintf("assert header %q required", DefaultAssertHeader) {
			t.Fatalf("Identify = %v", err)
		}
	})

	t.Run("header name is the caller and not a system role", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":%q}}],
			"roles": [
				{"name":"admin","bindings":[{"auth":"system","uid":%d}]},
				{"name":"reader","bindings":[{"auth":"caddy","name":"john"}]}
			]
		}`, self.Username, uid))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"john"}}}
		got, err := policy.Identify(req, unixPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != "john@"+socketName {
			t.Errorf("principal: got %q", got.Principal.GetName())
		}
		if !sameRoleNames(got.Roles, []RoleName{"reader"}) {
			t.Errorf("roles: got %v, want [reader]", got.Roles)
		}
	})

	t.Run("asserter with no matching role", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":%q}}],
			"roles": [{"name":"admin","bindings":[{"auth":"system","uid":%d}]}]
		}`, self.Username, uid))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"alice"}}}
		got, err := policy.Identify(req, unixPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != "alice@"+socketName {
			t.Errorf("principal: got %q", got.Principal.GetName())
		}
		if len(got.Roles) != 0 {
			t.Errorf("roles: got %v, want none", got.Roles)
		}
	})

	t.Run("custom header", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","header":"Remote-User","asserter":{"user":%q}}],
			"roles": [{"name":"reader","bindings":[{"auth":"caddy","name":"john"}]}]
		}`, self.Username))
		req := &http.Request{Header: http.Header{"Remote-User": []string{"john"}}}
		got, err := policy.Identify(req, unixPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != "john@"+socketName {
			t.Errorf("principal: got %q", got.Principal.GetName())
		}
	})

	t.Run("first matching asserter requires its header", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [
				{"name":"first","kind":"assert","header":"X-First","asserter":{"user":%q}},
				{"name":"second","kind":"assert","asserter":{"user":%q}}
			],
			"roles": [{"name":"reader","bindings":[{"auth":"second","name":"john"}]}]
		}`, self.Username, self.Username))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"john"}}}
		_, err := policy.Identify(req, unixPeer(t))
		if fmt.Sprint(err) != `assert header "X-First" required` {
			t.Fatalf("Identify = %v", err)
		}
	})

	t.Run("later asserter claims when an earlier one declines", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [
				{"name":"first","kind":"assert","header":"X-First","asserter":{"user":"definitely-not-me"}},
				{"name":"second","kind":"assert","asserter":{"user":%q}}
			],
			"roles": [{"name":"reader","bindings":[{"auth":"second","name":"john"}]}]
		}`, self.Username))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"john"}}}
		got, err := policy.Identify(req, unixPeer(t))
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.GetName() != "john@"+socketName {
			t.Errorf("principal: got %q", got.Principal.GetName())
		}
		if !sameRoleNames(got.Roles, []RoleName{"reader"}) {
			t.Errorf("roles: got %v, want [reader]", got.Roles)
		}
	})

	t.Run("multiple header values", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":%q}}],
			"roles": []
		}`, self.Username))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"alice", "bob"}}}
		_, err := policy.Identify(req, unixPeer(t))
		if fmt.Sprint(err) != fmt.Sprintf("assert header %q required", DefaultAssertHeader) {
			t.Fatalf("Identify = %v", err)
		}
	})

	t.Run("blank header", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":%q}}],
			"roles": []
		}`, self.Username))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"  "}}}
		_, err := policy.Identify(req, unixPeer(t))
		if fmt.Sprint(err) != fmt.Sprintf("assert header %q required", DefaultAssertHeader) {
			t.Fatalf("Identify = %v", err)
		}
	})

	t.Run("control character in header", func(t *testing.T) {
		policy := loadPolicy(t, fmt.Sprintf(`{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":%q}}],
			"roles": []
		}`, self.Username))
		req := &http.Request{Header: http.Header{DefaultAssertHeader: []string{"jo\nhn"}}}
		_, err := policy.Identify(req, unixPeer(t))
		if fmt.Sprint(err) != fmt.Sprintf("assert header %q required", DefaultAssertHeader) {
			t.Fatalf("Identify = %v", err)
		}
	})
}

func TestPolicy_load(t *testing.T) {
	t.Run("system bindings", func(t *testing.T) {
		policy := loadPolicy(t, `{
			"roles": [
				{
					"name": "admin",
					"bindings": [
						{"auth": "system", "uid": 0},
						{"auth": "system", "group": "secret-agent"}
					]
				}
			]
		}`)
		if _, ok := policy.Authenticators.Get(systemAuthenticatorName); !ok {
			t.Fatal("system authenticator missing")
		}
		admin := roleNamed(policy.Roles, "admin")
		if admin == nil || len(admin.Bindings) != 2 {
			t.Fatalf("admin bindings = %v", policy.Roles)
		}
	})

	t.Run("user and group arms together", func(t *testing.T) {
		mustReject(t, `{"roles":[{"name":"admin","bindings":[{"auth":"system","uid":0,"group":"wheel"}]}]}`,
			"linux binding must not set both a user and a group")
	})

	t.Run("empty linux binding", func(t *testing.T) {
		mustReject(t, `{"roles":[{"name":"admin","bindings":[{"auth":"system"}]}]}`,
			"linux binding must set a user (uid and/or user) or a group (gid and/or group)")
	})

	t.Run("duplicate role", func(t *testing.T) {
		mustReject(t, `{"roles":[{"name":"admin"},{"name":"admin"}]}`, `duplicate role "admin"`)
	})

	t.Run("empty role name", func(t *testing.T) {
		mustReject(t, `{"roles":[{"name":""}]}`, "role name must not be empty")
	})

	t.Run("assert asserter required", func(t *testing.T) {
		_, _, err := unmarshalAuthenticator([]byte(`{"name":"caddy","kind":"assert"}`), Authenticators{})
		if fmt.Sprint(err) != "assert authenticator asserter is required" {
			t.Fatalf("unmarshal = %v", err)
		}
	})

	t.Run("empty assert binding name", func(t *testing.T) {
		mustReject(t, `{
			"authenticators": [{"name":"caddy","kind":"assert","asserter":{"user":"caddy"}}],
			"roles": [{"name":"reader","bindings":[{"auth":"caddy"}]}]
		}`, "assert binding name must not be empty")
	})

	t.Run("unknown authenticator kind", func(t *testing.T) {
		mustReject(t, `{"authenticators":[{"name":"a","kind":"nope"}],"roles":[]}`,
			"authenticator prototype not found for nope")
	})

	t.Run("unknown authenticator name", func(t *testing.T) {
		mustReject(t, `{"roles":[{"name":"admin","bindings":[{"auth":"nope","uid":0}]}]}`,
			"authenticator not found for nope")
	})

	t.Run("duplicate authenticator", func(t *testing.T) {
		mustReject(t, `{
			"authenticators": [
				{"name":"caddy","kind":"assert","asserter":{"user":"caddy"}},
				{"name":"caddy","kind":"assert","asserter":{"user":"caddy"}}
			],
			"roles": []
		}`, `duplicate authenticator "caddy"`)
	})

	t.Run("explicit system", func(t *testing.T) {
		mustReject(t, `{
			"authenticators": [
				{"name":"system","kind":"linux"},
				{"name":"caddy","kind":"assert","asserter":{"user":"caddy"}}
			],
			"roles": []
		}`, `duplicate authenticator "system"`)
	})
}

func mustReject(t *testing.T, raw, want string) {
	t.Helper()
	err := json.Unmarshal([]byte(raw), new(Policy))
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != want {
		t.Errorf("error %q, want %q", err.Error(), want)
	}
}

func policyWith(t *testing.T, roles Roles) Policy {
	t.Helper()
	authenticators := NewAuthenticators()
	if err := authenticators.Add(systemAuthenticatorName, systemAuthenticator); err != nil {
		t.Fatal(err)
	}
	return Policy{Authenticators: authenticators, Roles: roles}
}

func loadPolicy(t *testing.T, raw string) Policy {
	t.Helper()
	var policy Policy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

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

func sameRoleNames(roles Roles, want []RoleName) bool {
	if len(roles) != len(want) {
		return false
	}
	for i, role := range roles {
		if role.Name != want[i] {
			return false
		}
	}
	return true
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
