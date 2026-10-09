package auth

import (
	"encoding/json"
	"net"
	"net/http"
)

type Policy struct {
	Authenticators Authenticators `json:"authenticators"`
	Roles          Roles          `json:"roles"`
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Authenticators Authenticators `json:"authenticators"`
		Roles          []struct {
			Name        RoleName               `json:"name"`
			Bindings    []json.RawMessage      `json:"bindings"`
			Permissions Permissions            `json:"permissions"`
			Secrets     map[string]Permissions `json:"secrets"`
		} `json:"roles"`
	}
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return err
	}

	authenticators := envelope.Authenticators
	if authenticators == nil {
		authenticators = Authenticators{}
	}
	if _, ok := authenticators[systemAuthenticator]; !ok {
		system, err := getAuthenticator(linuxKind)
		if err != nil {
			return err
		}
		authenticators[systemAuthenticator] = system
	}

	roles := make([]*Role, 0, len(envelope.Roles))
	for _, raw := range envelope.Roles {
		bindings := make(Bindings, 0, len(raw.Bindings))
		for _, item := range raw.Bindings {
			binding, err := UnmarshalJSONBinding(item, authenticators)
			if err != nil {
				return err
			}
			bindings = append(bindings, binding)
		}
		roles = append(roles, &Role{
			Name:        raw.Name,
			Bindings:    bindings,
			Permissions: raw.Permissions,
			Secrets:     raw.Secrets,
		})
	}
	catalog, err := newRoles(roles)
	if err != nil {
		return err
	}

	*p = Policy{Authenticators: authenticators, Roles: catalog}
	return nil
}

// Identify authenticates the caller and collects the roles whose bindings match.
// Assert authenticators are not consulted yet.
func (p Policy) Identify(request *http.Request, connection net.Conn) (*Identity, error) {
	authenticator, ok := p.Authenticators[systemAuthenticator]
	if !ok {
		var err error
		authenticator, err = getAuthenticator(linuxKind)
		if err != nil {
			return nil, err
		}
	}
	principal, err := authenticator.Authenticate(request, connection)
	if err != nil {
		return nil, err
	}
	roles, err := p.Roles.BoundRoles(principal)
	if err != nil {
		return nil, err
	}
	return &Identity{Principal: principal, Roles: roles}, nil
}

/*
{
  "authenticators": [
    { "name": "caddy", "kind": "assert", "header": "Remote-User", "asserter": { "user": "caddy" } }
  ],
  "roles": [
    {
      "name": "admin",
      "bindings": [
        { "auth": "system", "uid": 0 },
        { "auth": "system", "group": "secret-agent" },
        { "auth": "caddy", "name": "john" }
      ]
    }
  ]
}
*/
