package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
)

type Permissions struct {
	Roles  auth.Roles  `json:"roles"`
	Claims auth.Claims `json:"claims"`
}

type identityKey struct{}

func identityFromContext(ctx context.Context) *auth.Identity {
	identity, ok := ctx.Value(identityKey{}).(*auth.Identity)
	if !ok {
		return nil
	}
	return identity
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
		identity, err := p.Claims.ClaimIdentity(r, connection)
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusUnauthorized, err))
			return
		}

		err = p.Roles.AssertPermission(identity.Roles, permissions)
		if err != nil {
			writeError(w, NewErrorResponse(http.StatusForbidden, err))
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), identityKey{}, identity))
		next.ServeHTTP(w, r)
	})
}
