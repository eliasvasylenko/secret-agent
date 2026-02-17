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

func TestLoadPermissions(t *testing.T) {
	invalidPath := filepath.Join(t.TempDir(), "permissions.json")
	if err := os.WriteFile(invalidPath, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}

	validBody := `{"roles":{"admin":{"permissions":{"all":"any"}},"reader":{"permissions":{"secrets":"read","instances":"read"}}},"claims":{}}`
	validPath := filepath.Join(t.TempDir(), "permissions.json")
	if err := os.WriteFile(validPath, []byte(validBody), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		path       string
		checkErr   func(t *testing.T, err error)
		checkPerms func(t *testing.T, p *Permissions)
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
			checkPerms: func(t *testing.T, p *Permissions) {
				if p == nil {
					t.Fatal("LoadPermissions returned nil *Permissions")
				}
				if len(p.Roles) != 2 {
					t.Errorf("len(Roles) = %d, want 2", len(p.Roles))
				}
				if _, ok := p.Roles["admin"]; !ok {
					t.Error("missing role admin")
				}
				if _, ok := p.Roles["reader"]; !ok {
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
				if tt.checkErr != nil {
					tt.checkErr(t, err)
				}
			} else if err != nil {
				t.Fatalf("LoadPermissions = %v", err)
			}
			if tt.checkPerms != nil {
				tt.checkPerms(t, p)
			}
		})
	}
}

func TestPermissions_Middleware_returns401WhenClaimIdentityFails(t *testing.T) {
	// Use a non-Unix connection so ClaimIdentity fails (e.g. "unexpected socket type" on Linux).
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &Permissions{Roles: auth.Roles{"admin": {Name: "admin", Permissions: auth.Permissions{auth.All: auth.Any}}}}
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := p.Middleware(auth.Permissions{auth.Secrets: auth.Read}, next)

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
