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

func (e Environment) Render() []string {
	var vars []string
	for key, value := range e {
		vars = append(vars, fmt.Sprintf("%v=%v", key, value))
	}
	return vars
}

func (e Environment) ExpandWith(env Environment) Environment {
	if e == nil {
		return env
	}
	if env == nil {
		return e
	}
	merged := Environment{}
	for key, value := range e {
		merged[key] = env.Expand(value)
	}
	return merged
}

func (e Environment) ExpandAndMergeWith(env Environment) Environment {
	merged := e.ExpandWith(env)
	for key, value := range env {
		if _, ok := merged[key]; !ok {
			merged[key] = value
		}
	}
	return merged
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
