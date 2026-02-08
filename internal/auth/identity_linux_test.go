//go:build linux

package auth

import (
	"encoding/json"
	"net"
	"net/http"
	"os/user"
	"testing"
)

func slicesEqual(a, b ClaimedRoles) bool {
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

// claimedRolesSetEqual compares roles as sets (order-independent).
func claimedRolesSetEqual(a, b ClaimedRoles) bool {
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

func TestPlatformClaimsUnmarshalMarshal(t *testing.T) {
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
			var c PlatformClaims
			if err := json.Unmarshal([]byte(tc.json), &c); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			roundTrip, err := json.Marshal(c)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var c2 PlatformClaims
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
		claims        PlatformClaims
		user          *user.User
		groups        []*user.Group
		wantPrincipal string
		wantRoles     ClaimedRoles
	}{
		{
			name:          "empty claims yields principal only",
			claims:        PlatformClaims{},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     nil,
		},
		{
			name: "user matched by uid",
			claims: PlatformClaims{
				Users: map[Entity]ClaimedRoles{
					{Id: "1000", Name: ""}: {"admin"},
				},
			},
			user:          alice,
			groups:        nil,
			wantPrincipal: "linux:alice/1000",
			wantRoles:     ClaimedRoles{"admin"},
		},
		{
			name: "user matched by username",
			claims: PlatformClaims{
				Users: map[Entity]ClaimedRoles{
					{Id: "", Name: "alice"}: {"reader"},
				},
			},
			user:          alice,
			groups:        nil,
			wantPrincipal: "linux:alice/1000",
			wantRoles:     ClaimedRoles{"reader"},
		},
		{
			name: "user matched by id/name",
			claims: PlatformClaims{
				Users: map[Entity]ClaimedRoles{
					{Id: "1000", Name: "alice"}: {"writer"},
				},
			},
			user:          alice,
			groups:        nil,
			wantPrincipal: "linux:alice/1000",
			wantRoles:     ClaimedRoles{"writer"},
		},
		{
			name: "group matched by gid",
			claims: PlatformClaims{
				Groups: map[Entity]ClaimedRoles{
					{Id: "100", Name: ""}: {"reader"},
				},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     ClaimedRoles{"reader"},
		},
		{
			name: "group matched by name",
			claims: PlatformClaims{
				Groups: map[Entity]ClaimedRoles{
					{Id: "", Name: "users"}: {"reader"},
				},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     ClaimedRoles{"reader"},
		},
		{
			name: "user and group roles merged and deduplicated",
			claims: PlatformClaims{
				Users: map[Entity]ClaimedRoles{
					{Id: "1000", Name: ""}: {"admin", "reader"},
				},
				Groups: map[Entity]ClaimedRoles{
					{Id: "100", Name: ""}: {"reader", "writer"},
				},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     ClaimedRoles{"admin", "reader", "writer"},
		},
		{
			name: "no matching entity yields empty roles",
			claims: PlatformClaims{
				Users:  map[Entity]ClaimedRoles{{Id: "9999", Name: ""}: {"admin"}},
				Groups: map[Entity]ClaimedRoles{{Id: "9999", Name: ""}: {"admin"}},
			},
			user:          alice,
			groups:        []*user.Group{usersGroup},
			wantPrincipal: "linux:alice/1000",
			wantRoles:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			principal, roles := tc.claims.authorise(tc.user, tc.groups)
			if principal != tc.wantPrincipal {
				t.Errorf("principal: got %q, want %q", principal, tc.wantPrincipal)
			}
			if !claimedRolesSetEqual(roles, tc.wantRoles) {
				t.Errorf("roles: got %v, want %v", roles, tc.wantRoles)
			}
		})
	}
}

func TestClaimIdentity_nonUnixConn_returnsError(t *testing.T) {
	c := &PlatformClaims{}
	_, conn := net.Pipe()
	defer conn.Close()

	_, err := c.ClaimIdentity(&http.Request{}, conn)
	if err == nil {
		t.Error("expected error for non-UnixConn")
	}
	if err != nil && err.Error() != "unexpected socket type" {
		t.Errorf("expected 'unexpected socket type', got %v", err)
	}
}
