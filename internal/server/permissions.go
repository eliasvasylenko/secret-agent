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
	var names []auth.RoleName
	if identity := identityFromContext(r.Context()); identity != nil {
		names = make([]auth.RoleName, len(identity.Roles))
		for i, role := range identity.Roles {
			names[i] = role.Name
		}
	}
	writeError(w, NewErrorResponse(http.StatusForbidden, fmt.Errorf("operation not permitted with roles %v", names)))
	return false
}

func LoadPermissions(permissionsFileName string) (*auth.Policy, error) {
	permissionsFile, err := os.Open(permissionsFileName)
	if err != nil {
		return &auth.Policy{}, err
	}

	permissionsBytes, err := io.ReadAll(permissionsFile)
	if err != nil {
		return &auth.Policy{}, err
	}

	var policy auth.Policy
	err = json.Unmarshal(permissionsBytes, &policy)

	return &policy, err
}

func AuthMiddleware(policy *auth.Policy, permissions auth.Permissions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection := r.Context().Value(connectionKey{}).(net.Conn)
		identity, err := policy.Identify(r, connection)
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusUnauthorized, err))
			return
		}

		// No secret yet: the action must be granted globally or on some secret.
		err = identity.AssertPermission(permissions, "")
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusForbidden, err))
			return
		}

		permit := func(secretID string) bool {
			return identity.CheckPermission(permissions, secretID)
		}
		ctx := context.WithValue(r.Context(), identityKey{}, identity)
		ctx = contextWithPermit(ctx, permit)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
