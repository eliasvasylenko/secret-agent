//go:build linux

package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/user"
	"testing"
)

func TestBindingsUnmarshalForwardAuth(t *testing.T) {
	var b Bindings
	err := json.Unmarshal([]byte(`{"users":{"alice":["admin"]},"forwardAuth":{"peers":["caddy","33"],"header":"Remote-User"}}`), &b)
	if err != nil {
		t.Fatal(err)
	}
	if b.ForwardAuth == nil || b.ForwardAuth.Header != "Remote-User" || len(b.ForwardAuth.Peers) != 2 {
		t.Fatalf("forwardAuth: %+v", b.ForwardAuth)
	}
	if len(b.Users) != 1 {
		t.Fatalf("users: %v", b.Users)
	}
}

func TestBindings_Identify_forwardAuthHeader(t *testing.T) {
	self, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	wantPrincipal := fmt.Sprintf("linux:%s/%s", self.Username, self.Uid)

	t.Run("header ignored when peer is not a hop", func(t *testing.T) {
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

	t.Run("trusted hop requires header", func(t *testing.T) {
		conn := unixPeer(t)
		b := &Bindings{ForwardAuth: &ForwardAuth{Peers: []Entity{{Id: self.Uid}}}}
		_, err := b.Identify(&http.Request{}, conn)
		if err == nil {
			t.Fatal("expected error when hop omits user header")
		}
	})

	t.Run("trusted hop uses header for unknown user", func(t *testing.T) {
		conn := unixPeer(t)
		req := &http.Request{Header: http.Header{DefaultForwardAuthHeader: []string{"sa-remote-user"}}}
		b := &Bindings{
			PlatformBindings: PlatformBindings{
				Users: map[Entity]RoleNames{{Name: "sa-remote-user"}: {"reader"}},
			},
			ForwardAuth: &ForwardAuth{Peers: []Entity{{Name: self.Username}}},
		}
		got, err := b.Identify(req, conn)
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal != "http:sa-remote-user" {
			t.Errorf("principal: got %q, want http:sa-remote-user", got.Principal)
		}
		if !roleNamesSetEqual(got.Roles, RoleNames{"reader"}) {
			t.Errorf("roles: got %v, want [reader]", got.Roles)
		}
	})

	t.Run("trusted hop maps header to local user", func(t *testing.T) {
		conn := unixPeer(t)
		req := &http.Request{Header: http.Header{DefaultForwardAuthHeader: []string{self.Username}}}
		b := &Bindings{
			PlatformBindings: PlatformBindings{
				Users: map[Entity]RoleNames{{Id: self.Uid}: {"admin"}},
			},
			ForwardAuth: &ForwardAuth{Peers: []Entity{{Id: self.Uid}}},
		}
		got, err := b.Identify(req, conn)
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

	t.Run("custom header name", func(t *testing.T) {
		conn := unixPeer(t)
		req := &http.Request{Header: http.Header{"Remote-User": []string{"sa-remote-user"}}}
		b := &Bindings{
			ForwardAuth: &ForwardAuth{
				Peers:  []Entity{{Id: self.Uid}},
				Header: "Remote-User",
			},
		}
		got, err := b.Identify(req, conn)
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal != "http:sa-remote-user" {
			t.Errorf("principal: got %q, want http:sa-remote-user", got.Principal)
		}
	})

	t.Run("rejects multiple header values", func(t *testing.T) {
		conn := unixPeer(t)
		req := &http.Request{Header: http.Header{DefaultForwardAuthHeader: []string{"alice", "bob"}}}
		b := &Bindings{ForwardAuth: &ForwardAuth{Peers: []Entity{{Id: self.Uid}}}}
		_, err := b.Identify(req, conn)
		if err == nil {
			t.Fatal("expected error for multiple forward-auth user headers")
		}
	})
}
