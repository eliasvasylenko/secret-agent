package mocks

import (
	"fmt"
	"reflect"
	"runtime"
)

type Mock struct {
	callIndex int
	calls     []MockCall
}

type MockCall struct {
	name string
	mock any
}

func Expect[T any](m *Mock, f T, t T) {
	m.calls = append(m.calls, MockCall{
		name: runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name(),
		mock: t,
	})
}

func nextCall[T any](m *Mock, f T) T {
	name := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	callIndex := m.callIndex
	m.callIndex++
	call := m.calls[callIndex]
	if name != call.name {
		panic(fmt.Sprintf("Expecting call '%s', got '%s'", call.name, name))
	}
	return call.mock.(T)
}
