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
	Register(assertKind, func() Authenticator[assertCredential] { return &assertAuthenticator{} })
}

// assertCredential is the name written by a peer that matched the asserter binding.
type assertCredential struct {
	name string
}

func (c assertCredential) Name() string {
	return c.name
}

// assertAuthenticator claims the connection when the socket peer matches its
// asserter and its header is present. An unmatched peer or absent header does
// not match. A present header that is not a single clean name is a failure.
type assertAuthenticator struct {
	header   string
	asserter linuxBinding
}

func (a assertAuthenticator) Authenticate(request *http.Request, connection net.Conn) (assertCredential, error) {
	peer, err := authenticatePeer(connection)
	if err != nil {
		return assertCredential{}, err
	}
	matched, err := a.asserter.Bind(peer)
	if err != nil {
		return assertCredential{}, err
	}
	if !matched {
		return assertCredential{}, errNotClaimed
	}
	header := a.header
	if header == "" {
		header = DefaultAssertHeader
	}
	name, err := headerValue(request, header)
	if err != nil {
		return assertCredential{}, err
	}
	return assertCredential{name: name}, nil
}

func (assertAuthenticator) NewBinding() Binding[assertCredential] {
	return &assertBinding{}
}

func (a *assertAuthenticator) unmarshal(data []byte) error {
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
	err = json.Unmarshal(raw.Asserter, &a.asserter)
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

func (b assertBinding) Bind(credential assertCredential) (bool, error) {
	if b.Name == "" {
		return false, fmt.Errorf("assert binding name must not be empty")
	}
	return b.Name == credential.name, nil
}

func headerValue(request *http.Request, header string) (string, error) {
	if request == nil {
		return "", errNotClaimed
	}
	values := request.Header.Values(header)
	if len(values) == 0 {
		return "", errNotClaimed
	}
	if len(values) != 1 {
		return "", fmt.Errorf("assert header %q invalid", header)
	}
	name := strings.TrimSpace(values[0])
	if name == "" || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("assert header %q invalid", header)
	}
	return name, nil
}
