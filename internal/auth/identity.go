//go:build linux

package auth

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/eliasvasylenko/secret-agent/internal/marshal"
)

type Identity struct {
	Principal string
	Roles     ClaimedRoles
}

type Claims struct {
	PlatformClaims `json:""`
}

func (c *Claims) ClaimIdentity(request *http.Request, connection net.Conn) (*Identity, error) {
	return c.PlatformClaims.ClaimIdentity(request, connection)
}

type ClaimedRoles []RoleName

func (c *ClaimedRoles) UnmarshalJSON(p []byte) error {
	var claimedRole RoleName
	err1 := json.Unmarshal(p, &claimedRole)
	if err1 == nil {
		*c = ClaimedRoles{claimedRole}
		return nil
	}
	var temp []RoleName
	err2 := json.Unmarshal(p, &temp)
	if err2 != nil {
		return errors.Join(err1, err2)
	}
	*c = temp
	return nil
}

func (c *ClaimedRoles) MarshalJSON() ([]byte, error) {
	if len(*c) == 1 {
		return marshal.JSON((*c)[0])
	}
	return marshal.JSON([]RoleName(*c))
}
