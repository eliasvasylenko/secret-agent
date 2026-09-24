package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
)

type Permissions struct {
	Roles    auth.Roles    `json:"roles"`
	Bindings auth.Bindings `json:"bindings"`
}

type identityKey struct{}

func identityFromContext(ctx context.Context) *auth.Identity {
	identity, ok := ctx.Value(identityKey{}).(*auth.Identity)
	if !ok {
		return nil
	}
	return identity
}

// permitFunc reports whether the route's permission set allows one secret.
type permitFunc func(secretID string) bool

type permitKey struct{}

func contextWithPermit(ctx context.Context, permit permitFunc) context.Context {
	return context.WithValue(ctx, permitKey{}, permit)
}

func permitFromContext(ctx context.Context) permitFunc {
	permit, _ := ctx.Value(permitKey{}).(permitFunc)
	return permit
}

func permitted(r *http.Request, secretID string) bool {
	permit := permitFromContext(r.Context())
	return permit != nil && permit(secretID)
}

func requirePermit(w http.ResponseWriter, r *http.Request, secretID string) bool {
	if permitted(r, secretID) {
		return true
	}
	var roles auth.RoleNames
	if identity := identityFromContext(r.Context()); identity != nil {
		roles = identity.Roles
	}
	writeError(w, NewErrorResponse(http.StatusForbidden, fmt.Errorf("operation not permitted with roles %v", roles)))
	return false
}

func LoadPermissions(permissionsFileName string) (*Permissions, error) {
	permissionsFile, err := os.Open(permissionsFileName)
	if err != nil {
		return &Permissions{}, err
	}

	permissionsBytes, err := io.ReadAll(permissionsFile)
	if err != nil {
		return &Permissions{}, err
	}

	var permissions Permissions
	err = json.Unmarshal(permissionsBytes, &permissions)

	return &permissions, err
}

func (p *Permissions) Middleware(permissions auth.Permissions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection := r.Context().Value(connectionKey{}).(net.Conn)
		identity, err := p.Bindings.Identify(r, connection)
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusUnauthorized, err))
			return
		}

		// No secret yet: the action must be granted globally or on some secret.
		err = p.Roles.AssertPermission(identity.Roles, permissions, "")
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusForbidden, err))
			return
		}

		permit := func(secretID string) bool {
			return p.Roles.CheckPermission(identity.Roles, permissions, secretID)
		}
		ctx := context.WithValue(r.Context(), identityKey{}, identity)
		ctx = contextWithPermit(ctx, permit)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
