package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
)

func roleLoaded(p *auth.Policy, name auth.RoleName) bool {
	for _, role := range p.Roles {
		if role.Name == name {
			return true
		}
	}
	return false
}

func TestLoadPermissions(t *testing.T) {
	invalidPath := filepath.Join(t.TempDir(), "permissions.json")
	if err := os.WriteFile(invalidPath, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	validBody := `{"roles":[{"name":"admin","bindings":[{"auth":"system","uid":0}],"permissions":{"all":"any"}},{"name":"reader","permissions":{"secrets":"read","instances":"read"}}]}`
	validPath := filepath.Join(t.TempDir(), "permissions.json")
	if err := os.WriteFile(validPath, []byte(validBody), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		path       string
		checkErr   func(t *testing.T, err error)
		checkPerms func(t *testing.T, p *auth.Policy)
	}{
		{
			name: "missing file",
			path: filepath.Join(t.TempDir(), "nonexistent"),
			checkErr: func(t *testing.T, err error) {
				if !os.IsNotExist(err) {
					t.Errorf("err = %v, want os.IsNotExist", err)
				}
			},
		},
		{
			name: "invalid JSON",
			path: invalidPath,
			checkErr: func(t *testing.T, err error) {
				if _, ok := err.(*json.SyntaxError); !ok {
					t.Errorf("err = %T, want *json.SyntaxError", err)
				}
			},
		},
		{
			name: "valid file",
			path: validPath,
			checkPerms: func(t *testing.T, p *auth.Policy) {
				if p == nil {
					t.Fatal("LoadPermissions returned nil *auth.Policy")
				}
				if _, ok := p.Authenticators.Get("system"); !ok {
					t.Error("system authenticator missing")
				}
				if len(p.Roles) != 2 {
					t.Errorf("len(Roles) = %d, want 2", len(p.Roles))
				}
				if !roleLoaded(p, "admin") {
					t.Error("missing role admin")
				}
				if !roleLoaded(p, "reader") {
					t.Error("missing role reader")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := LoadPermissions(tt.path)
			if tt.checkErr != nil {
				if err == nil {
					t.Fatal("LoadPermissions = nil, want error")
				}
				tt.checkErr(t, err)
			} else if err != nil {
				t.Fatalf("LoadPermissions = %v", err)
			}
			if tt.checkPerms != nil {
				tt.checkPerms(t, p)
			}
		})
	}
}

func TestPermissions_Middleware_returns401WhenIdentifyFails(t *testing.T) {
	// Use a non-Unix connection so Identify fails (e.g. "unexpected socket type" on Linux).
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var policy auth.Policy
	if err := json.Unmarshal([]byte(`{"roles":[{"name":"admin","permissions":{"all":"any"}}]}`), &policy); err != nil {
		t.Fatal(err)
	}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := AuthMiddleware(&policy, auth.Permissions{auth.Secrets: auth.Read}, next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), connectionKey{}, server))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Error("next handler was called (should be rejected with 401)")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
