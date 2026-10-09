package auth

import (
	"encoding/json"
	"fmt"
)

type Policy struct {
	Authenticators Authenticators `json:"authenticators"`
	Roles          Roles          `json:"roles"`
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var envelope struct {
		Authenticators Authenticators `json:"authenticators"`
		Roles          map[RoleName]struct {
			Bindings    []json.RawMessage      `json:"bindings"`
			Permissions Permissions            `json:"permissions"`
			Secrets     map[string]Permissions `json:"secrets"`
		} `json:"roles"`
	}
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return err
	}

	roles := make(Roles, len(envelope.Roles))
	for name, raw := range envelope.Roles {
		if name == "" {
			return fmt.Errorf("role name must not be empty")
		}
		bindings := make(Bindings, 0, len(raw.Bindings))
		for _, item := range raw.Bindings {
			binding, err := UnmarshalJSONBinding(item, envelope.Authenticators)
			if err != nil {
				return err
			}
			bindings = append(bindings, binding)
		}
		roles[name] = Role{
			Name:        name,
			Bindings:    bindings,
			Permissions: raw.Permissions,
			Secrets:     raw.Secrets,
		}
	}

	*p = Policy{Authenticators: envelope.Authenticators, Roles: roles}
	return nil
}

/*
{
  "authenticators": [
    { "name": "caddy", "kind": "assert", "header": "Remote-User", "asserter": { "user": "caddy" } }
  ],
  "roles": {
    "admin": {
      "bindings": [
        { "auth": "system", "uid": 0 },
        { "auth": "system", "group": "secret-agent" },
        { "auth": "caddy", "name": "john" }
      ]
    }
  }
}
*/
