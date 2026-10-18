package auth

import (
	"encoding/json"
	"net"
	"net/http"
)

type Policy struct {
	Authenticators *Authenticators `json:"authenticators"`
	Roles          Roles           `json:"roles"`
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Authenticators json.RawMessage `json:"authenticators"`
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

	authenticators := NewAuthenticators()
	err = authenticators.Add(systemAuthenticatorName, systemAuthenticator)
	if err != nil {
		return err
	}
	err = authenticators.unmarshal(envelope.Authenticators, authenticators)
	if err != nil {
		return err
	}

	roles := make([]*Role, 0, len(envelope.Roles))
	for _, raw := range envelope.Roles {
		bindings := make(Bindings, 0, len(raw.Bindings))
		for _, item := range raw.Bindings {
			binding, err := unmarshalBinding(item, authenticators)
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

func (p Policy) Identify(request *http.Request, connection net.Conn) (*Identity, error) {
	principal, err := p.Authenticators.Authenticate(request, connection)
	if err != nil {
		return nil, err
	}
	roles, err := p.Roles.BoundRoles(principal)
	if err != nil {
		return nil, err
	}
	return &Identity{Principal: principal, Roles: roles}, nil
}
