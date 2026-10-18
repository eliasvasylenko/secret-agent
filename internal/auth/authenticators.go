package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
)

// errNotClaimed means this authenticator does not apply to the connection.
var errNotClaimed = errors.New("authenticator did not claim the connection")

const systemAuthenticatorName = "system"

var authenticatorRegistry = make(map[string]func() Authenticator[Credential])

type Authenticators struct {
	order          []string
	authenticators map[string]Authenticator[Credential]
}

func NewAuthenticators() *Authenticators {
	return &Authenticators{
		order:          make([]string, 0),
		authenticators: make(map[string]Authenticator[Credential]),
	}
}

func (a *Authenticators) unmarshal(data []byte, existing *Authenticators) error {
	var list []json.RawMessage
	if len(data) > 0 {
		err := json.Unmarshal(data, &list)
		if err != nil {
			return err
		}
	}
	existingOrder := existing.order
	existingAuthenticators := existing.authenticators
	*a = Authenticators{
		order:          make([]string, len(list)+len(existingOrder)),
		authenticators: make(map[string]Authenticator[Credential]),
	}
	for i, name := range existingOrder {
		(*a).order[len(list)+i] = name
		(*a).authenticators[name] = existingAuthenticators[name]
	}
	for i := len(list) - 1; i >= 0; i-- {
		name, authenticator, err := unmarshalAuthenticator(list[i], *a)
		if err != nil {
			return err
		}
		if _, ok := (*a).authenticators[name]; ok {
			return fmt.Errorf("duplicate authenticator %q", name)
		}
		(*a).order[i] = name
		(*a).authenticators[name] = authenticator
	}
	return nil
}

func (a *Authenticators) Add(name string, authenticator Authenticator[Credential]) error {
	if err := validateAuthenticatorName(name); err != nil {
		return err
	}
	if _, ok := (*a).authenticators[name]; ok {
		return fmt.Errorf("duplicate authenticator %q", name)
	}
	a.order = append([]string{name}, a.order...)
	a.authenticators[name] = authenticator
	return nil
}

func (a *Authenticators) Get(name string) (Authenticator[Credential], bool) {
	authenticator, ok := a.authenticators[name]
	return authenticator, ok
}

func (a *Authenticators) Authenticate(request *http.Request, connection net.Conn) (Principal, error) {
	for _, name := range a.order {
		authenticator, ok := a.authenticators[name]
		if !ok {
			continue
		}
		credential, err := authenticator.Authenticate(request, connection)
		if errors.Is(err, errNotClaimed) {
			continue
		}
		if err != nil {
			return Principal{}, err
		}
		return Principal{authenticator: name, credential: credential}, nil
	}
	return Principal{}, fmt.Errorf("failed to authenticate")
}

func validateAuthenticatorName(name string) error {
	if name == "" || strings.Contains(name, "@") {
		return fmt.Errorf("authenticator name %q must be non-empty and must not contain '@'", name)
	}
	return nil
}

// Credential is the caller an authenticator authenticated.
// Name is that authenticator's name for the caller. Principal.GetName qualifies it.
type Credential interface {
	Name() string
}

// Principal is the caller named by the authenticator that claimed the connection.
// GetName is Name, then @, then that authenticator's name.
type Principal struct {
	authenticator string
	credential    Credential
}

func (p Principal) GetName() string {
	if p.credential == nil {
		return ""
	}
	return p.credential.Name() + "@" + p.authenticator
}

type Authenticator[T Credential] interface {
	Authenticate(request *http.Request, connection net.Conn) (T, error)

	NewBinding() Binding[T]

	unmarshal([]byte, Authenticators) error
}

type Bindings []Binding[Credential]

type Binding[T Credential] interface {
	Bind(credential T) (bool, error)

	json.Unmarshaler
}

type AnyAuthenticator[T Credential] struct {
	authenticator Authenticator[T]
}

type AnyBinding[T Credential] struct {
	binding Binding[T]
}

func (a AnyAuthenticator[T]) Authenticate(request *http.Request, connection net.Conn) (Credential, error) {
	return a.authenticator.Authenticate(request, connection)
}

func (a AnyAuthenticator[T]) NewBinding() Binding[Credential] {
	return AnyBinding[T]{binding: a.authenticator.NewBinding()}
}

func (a AnyAuthenticator[T]) unmarshal(data []byte, authenticators Authenticators) error {
	return a.authenticator.unmarshal(data, authenticators)
}

func (a AnyBinding[T]) Bind(credential Credential) (bool, error) {
	typed, ok := credential.(T)
	if !ok {
		return false, nil
	}
	return a.binding.Bind(typed)
}

func (a AnyBinding[T]) UnmarshalJSON(data []byte) error {
	return a.binding.UnmarshalJSON(data)
}

func RegisterAuthenticatorPrototype[T Credential](name string, authenticatorPrototype *Authenticator[T]) {
	t := reflect.TypeOf(*authenticatorPrototype)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic(fmt.Sprintf("authenticator prototype for %s must be a struct", name))
	}

	authenticatorRegistry[name] = func() Authenticator[Credential] {
		fresh := reflect.New(t).Interface().(Authenticator[T])
		return AnyAuthenticator[T]{authenticator: fresh}
	}
}

func getAuthenticatorPrototype(kind string) (Authenticator[Credential], error) {
	factory, ok := authenticatorRegistry[kind]
	if !ok {
		return nil, fmt.Errorf("authenticator prototype not found for %s", kind)
	}
	return factory(), nil
}

func unmarshalAuthenticator(data []byte, available Authenticators) (string, Authenticator[Credential], error) {
	var envelope struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return "", nil, err
	}
	if err := validateAuthenticatorName(envelope.Name); err != nil {
		return "", nil, err
	}

	prototype, err := getAuthenticatorPrototype(envelope.Kind)
	if err != nil {
		return "", nil, err
	}

	err = prototype.unmarshal(data, available)
	if err != nil {
		return "", nil, err
	}

	return envelope.Name, prototype, nil
}

func unmarshalBinding(data []byte, authenticators *Authenticators) (Binding[Credential], error) {
	var envelope struct {
		Authenticator string `json:"auth"`
	}
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return nil, err
	}
	if envelope.Authenticator == "" {
		envelope.Authenticator = systemAuthenticatorName
	}

	authenticator, ok := authenticators.Get(envelope.Authenticator)
	if !ok {
		return nil, fmt.Errorf("authenticator not found for %s", envelope.Authenticator)
	}

	binding := authenticator.NewBinding()
	err = binding.UnmarshalJSON(data)

	return binding, err
}
