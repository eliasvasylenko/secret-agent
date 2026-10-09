package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"reflect"
)

var authenticatorRegistry = make(map[string]func() Authenticator[Principal])

type Authenticators map[string]Authenticator[Principal]

func (a *Authenticators) UnmarshalJSON(data []byte) error {
	var list []json.RawMessage
	err := json.Unmarshal(data, &list)
	if err != nil {
		return err
	}
	*a = make(Authenticators, len(list))
	for _, item := range list {
		name, authenticator, err := UnmarshalJSONAuthenticator(item)
		if err != nil {
			return err
		}
		if _, ok := (*a)[name]; ok {
			return fmt.Errorf("duplicate authenticator %q", name)
		}
		(*a)[name] = authenticator
	}
	return nil
}

type Authenticator[T Principal] interface {
	Authenticate(request *http.Request, connection net.Conn) (T, error)

	NewBinding() Binding[T]

	json.Unmarshaler
}

type Principal interface {
	GetName() string
}

type Bindings []Binding[Principal]

type Binding[T Principal] interface {
	Bind(principal T) (bool, error)

	json.Unmarshaler
}

type AnyAuthenticator[T Principal] struct {
	authenticator Authenticator[T]
}

type AnyBinding[T Principal] struct {
	binding Binding[T]
}

func (a AnyAuthenticator[T]) Authenticate(request *http.Request, connection net.Conn) (Principal, error) {
	return a.authenticator.Authenticate(request, connection)
}

func (a AnyAuthenticator[T]) NewBinding() Binding[Principal] {
	return AnyBinding[T]{binding: a.authenticator.NewBinding()}
}

func (a AnyAuthenticator[T]) UnmarshalJSON(data []byte) error {
	return a.authenticator.UnmarshalJSON(data)
}

func (a AnyBinding[T]) Bind(principal Principal) (bool, error) {
	return a.binding.Bind(principal.(T))
}

func (a AnyBinding[T]) UnmarshalJSON(data []byte) error {
	return a.binding.UnmarshalJSON(data)
}

func RegisterAuthenticatorPrototype[T Principal](name string, authenticatorPrototype *Authenticator[T]) {
	t := reflect.TypeOf(*authenticatorPrototype)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic(fmt.Sprintf("authenticator prototype for %s must be a struct", name))
	}

	authenticatorRegistry[name] = func() Authenticator[Principal] {
		fresh := reflect.New(t).Interface().(Authenticator[T])
		return AnyAuthenticator[T]{authenticator: fresh}
	}
}

func getAuthenticator(kind string) (Authenticator[Principal], error) {
	factory, ok := authenticatorRegistry[kind]
	if !ok {
		return nil, fmt.Errorf("authenticator prototype not found for %s", kind)
	}
	return factory(), nil
}

func UnmarshalJSONAuthenticator(data []byte) (string, Authenticator[Principal], error) {
	var envelope struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return "", nil, err
	}

	authenticator, err := getAuthenticator(envelope.Kind)
	if err != nil {
		return "", nil, err
	}

	err = authenticator.UnmarshalJSON(data)
	if err != nil {
		return "", nil, err
	}

	return envelope.Name, authenticator, nil
}

func UnmarshalJSONBinding(data []byte, authenticators Authenticators) (Binding[Principal], error) {
	var envelope struct {
		Authenticator string `json:"auth"`
	}
	err := json.Unmarshal(data, &envelope)
	if err != nil {
		return nil, err
	}

	authenticator, ok := authenticators[envelope.Authenticator]
	if !ok {
		return nil, fmt.Errorf("authenticator not found for %s", envelope.Authenticator)
	}

	binding := authenticator.NewBinding()
	err = binding.UnmarshalJSON(data)

	return binding, err
}
