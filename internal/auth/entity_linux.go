//go:build linux

package auth

import (
	"fmt"
	"strconv"
	"strings"
)

// Entity is a unique identifier for a user or group.
// It is represented as a string in the format "id", "name", or "id/name".
type Entity struct {
	Id   string
	Name string
}

// MarshalText implements encoding.TextMarshaler for use as JSON object keys.
func (e Entity) MarshalText() ([]byte, error) {
	if e.Id == "" {
		return []byte(e.Name), nil
	}
	if e.Name == "" {
		return []byte(e.Id), nil
	}
	return []byte(e.Id + "/" + e.Name), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for use as JSON object keys.
func (e *Entity) UnmarshalText(text []byte) error {
	s := string(text)
	parts := strings.SplitN(s, "/", 2)
	if _, err := strconv.ParseInt(parts[0], 10, 33); err == nil {
		e.Id = parts[0]
		if len(parts) == 2 {
			e.Name = parts[1]
		} else {
			e.Name = ""
		}
	} else if len(parts) == 1 {
		e.Id = ""
		e.Name = parts[0]
	} else {
		return fmt.Errorf("invalid entity string: %s", s)
	}
	return nil
}

// entityMatches returns true if the entity key matches the given id and name.
func (e Entity) matches(id string, name string) bool {
	return (e.Id == "" || e.Id == id) && (e.Name == "" || e.Name == name)
}
