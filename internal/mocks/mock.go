package mocks

import (
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

type Mock struct {
	callIndex int
	calls     []MockCall
}

type MockCall struct {
	name string
	mock any
}

func Expect[T any](m *Mock, methodHandle T, mockFn T) {
	m.calls = append(m.calls, MockCall{
		name: runtime.FuncForPC(reflect.ValueOf(methodHandle).Pointer()).Name(),
		mock: mockFn,
	})
}

func nextCall[T any](m *Mock, methodHandle T) T {
	name := runtime.FuncForPC(reflect.ValueOf(methodHandle).Pointer()).Name()
	callIndex := m.callIndex
	m.callIndex++
	if callIndex >= len(m.calls) {
		panic(fmt.Sprintf("mock: expected %d call(s), got %d", len(m.calls), callIndex))
	}
	call := m.calls[callIndex]
	if name != call.name {
		panic(fmt.Sprintf("mock: expecting call '%s', got '%s'", call.name, name))
	}
	return call.mock.(T)
}

// Validate asserts that every expected call was made. Call it with defer after creating a mock in a test.
func (m *Mock) Validate(t testing.TB) {
	t.Helper()
	if m.callIndex != len(m.calls) {
		t.Errorf("mock: expected %d call(s), got %d", len(m.calls), m.callIndex)
	}
}
