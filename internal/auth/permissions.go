package auth

import (
	"encoding/json"
	"fmt"
)

// A set of permissions. A subject or action outside the known constants is rejected at load.
type Permissions map[Subject]Action

// Subjects which can be acted upon
type Subject string

const (
	// All subjects
	All Subject = "all"
	// Secrets subject
	Secrets Subject = "secrets"
	// Instances subject
	Instances Subject = "instances"
)

// Actions which can be performed upon subjects
type Action string

const (
	// Any action
	Any Action = "any"
	// List action
	List Action = "list"
	// Read action
	Read Action = "read"
	// Write action
	Write Action = "write"
)

func (p *Permissions) UnmarshalJSON(data []byte) error {
	var raw map[Subject]Action
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for subject, action := range raw {
		switch subject {
		case All, Secrets, Instances:
		default:
			return fmt.Errorf("invalid subject %q", subject)
		}
		switch action {
		case Any, List, Read, Write:
		default:
			return fmt.Errorf("invalid action %q", action)
		}
	}
	*p = raw
	return nil
}

func (p Permissions) matches(subject Subject, action Action) bool {
	if permitted, ok := p[subject]; ok && (permitted == action || permitted == Any) {
		return true
	}
	permitted, ok := p[All]
	return ok && (permitted == action || permitted == Any)
}
