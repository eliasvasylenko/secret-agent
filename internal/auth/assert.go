package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"unicode"
)

const assertKind = "assert"

func init() {
	var prototype Authenticator[assertPrincipal] = &assertAuthenticator{}
	RegisterAuthenticatorPrototype(assertKind, &prototype)
}

// assertPrincipal is a name written by a peer that matched the asserter binding.
// GetName is the header value, then @, then that peer's name.
type assertPrincipal struct {
	name string
	peer Principal
}

func (p assertPrincipal) GetName() string {
	return p.name + "@" + p.peer.GetName()
}

// assertAuthenticator claims the connection when the peer matches asserter,
// then requires that authenticator's header. The asserter is any binding.
type assertAuthenticator struct {
	header   string
	asserter Binding[Principal]
}

func (a assertAuthenticator) Authenticate(request *http.Request, connection net.Conn) (assertPrincipal, error) {
	if a.asserter == nil {
		return assertPrincipal{}, fmt.Errorf("assert authenticator asserter is required")
	}
	system, err := getAuthenticatorPrototype(linuxKind)
	if err != nil {
		return assertPrincipal{}, err
	}
	peer, err := system.Authenticate(request, connection)
	if err != nil {
		return assertPrincipal{}, err
	}
	matches, err := a.asserter.Bind(peer)
	if err != nil {
		return assertPrincipal{}, err
	}
	if !matches {
		return assertPrincipal{}, errNotClaimed
	}
	header := a.header
	if header == "" {
		header = DefaultAssertHeader
	}
	name, err := headerValue(request, header)
	if err != nil {
		return assertPrincipal{}, err
	}
	return assertPrincipal{name: name, peer: peer}, nil
}

func (assertAuthenticator) NewBinding() Binding[assertPrincipal] {
	return &assertBinding{}
}

func (a *assertAuthenticator) unmarshal(data []byte, existing Authenticators) error {
	var raw struct {
		Header   string          `json:"header"`
		Asserter json.RawMessage `json:"asserter"`
	}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}
	if len(raw.Asserter) == 0 || string(raw.Asserter) == "null" {
		return fmt.Errorf("assert authenticator asserter is required")
	}
	a.asserter, err = unmarshalBinding(raw.Asserter, &existing)
	if err != nil {
		return err
	}
	a.header = raw.Header
	return nil
}

type assertBinding struct {
	Name string `json:"name"`
}

func (b *assertBinding) UnmarshalJSON(data []byte) error {
	type plain assertBinding
	var raw plain
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}
	if raw.Name == "" {
		return fmt.Errorf("assert binding name must not be empty")
	}
	*b = assertBinding(raw)
	return nil
}

func (b assertBinding) Bind(principal assertPrincipal) (bool, error) {
	if b.Name == "" {
		return false, fmt.Errorf("assert binding name must not be empty")
	}
	return b.Name == principal.name, nil
}

func headerValue(request *http.Request, header string) (string, error) {
	if request == nil {
		return "", fmt.Errorf("assert header %q required", header)
	}
	values := request.Header.Values(header)
	if len(values) != 1 {
		return "", fmt.Errorf("assert header %q required", header)
	}
	name := strings.TrimSpace(values[0])
	if name == "" || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("assert header %q required", header)
	}
	return name, nil
}
