package command

import (
	"fmt"
	"maps"
	"os"
	"strings"
)

// The environment for a command
type Environment map[string]string

func NewEnvironment() Environment {
	return make(Environment)
}

func (e Environment) Load(vars []string) Environment {
	for _, variable := range vars {
		keyvalue := strings.SplitN(variable, "=", 2)
		e[keyvalue[0]] = keyvalue[1]
	}
	return e
}

func (e Environment) Render(vars []string) []string {
	for i, variable := range vars {
		keyvalue := strings.SplitN(variable, "=", 2)
		vars[i] = fmt.Sprintf("%v=%v", keyvalue[0], e.Expand(keyvalue[1]))
	}
	for key := range e {
		value := e.Substitute(key)
		vars = append(vars, fmt.Sprintf("%v=%v", key, value))
	}
	return vars
}

func (e Environment) Merge(env Environment) Environment {
	if e == nil {
		return env
	}
	if env == nil {
		return e
	}
	merged := maps.Clone(e)
	for key, value := range env {
		if _, ok := merged[key]; !ok {
			merged[key] = value
		}
	}
	return merged
}

func (e Environment) Substitute(key string) string {
	substitution, ok := e[key]
	if ok {
		n := maps.Clone(e)
		delete(n, key)
		return n.Expand(substitution)
	} else {
		return fmt.Sprintf("${%s}", key)
	}
}

func (e Environment) Expand(s string) string {
	if e == nil {
		return s
	}
	return os.Expand(s, func(key string) string {
		n := maps.Clone(e)
		delete(n, key)
		substitution, ok := e[key]
		if ok {
			return n.Expand(substitution)
		} else {
			return fmt.Sprintf("${%s}", key)
		}
	})
}
