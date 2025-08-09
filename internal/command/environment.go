package command

import (
	"fmt"
	"maps"
	"os"
)

// The environment for a command
type Environment map[string]string

func (e Environment) Render() []string {
	vars := make([]string, len(e))
	for key, value := range e {
		vars = append(vars, fmt.Sprintf("%v=%v", key, value))
	}
	return vars
}

func (e Environment) Expand(s string) string {
	return os.Expand(s, func(key string) string {
		n := maps.Clone(e)
		delete(n, key)
		return n.Expand(e[key])
	})
}
