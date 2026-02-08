//go:build linux

package auth

import (
	"encoding/json"
	"testing"
)

func TestEntityMatches(t *testing.T) {
	tests := []struct {
		entity Entity
		id     string
		name   string
		want   bool
	}{
		{Entity{Id: "1000", Name: "alice"}, "1000", "alice", true},
		{Entity{Id: "1000", Name: ""}, "1000", "alice", true},
		{Entity{Id: "", Name: "alice"}, "1000", "alice", true},
		{Entity{Id: "", Name: ""}, "1000", "alice", true},
		{Entity{Id: "1000", Name: "alice"}, "1000", "bob", false},
		{Entity{Id: "1000", Name: "alice"}, "1001", "alice", false},
	}
	for _, tc := range tests {
		got := tc.entity.matches(tc.id, tc.name)
		if got != tc.want {
			t.Errorf("Entity%+v.matches(%q, %q): expected %v, got %v", tc.entity, tc.id, tc.name, tc.want, got)
		}
	}
}

func TestEntityUnmarshalJSON(t *testing.T) {
	tests := []struct {
		json string
		want Entity
	}{
		{`"1000"`, Entity{Id: "1000", Name: ""}},
		{`"alice"`, Entity{Id: "", Name: "alice"}},
		{`"1000/alice"`, Entity{Id: "1000", Name: "alice"}},
	}
	for _, tc := range tests {
		var got Entity
		if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
			t.Errorf("Unmarshal(%s): %v", tc.json, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Unmarshal(%s): expected %+v, got %+v", tc.json, tc.want, got)
		}
	}
}

func TestEntityMarshalJSON(t *testing.T) {
	tests := []struct {
		entity Entity
		want   string
	}{
		{Entity{Id: "1000", Name: ""}, `"1000"`},
		{Entity{Id: "", Name: "alice"}, `"alice"`},
		{Entity{Id: "1000", Name: "alice"}, `"1000/alice"`},
	}
	for _, tc := range tests {
		got, err := json.Marshal(&tc.entity)
		if err != nil {
			t.Errorf("Marshal(%+v): %v", tc.entity, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("Marshal(%+v): expected %s, got %s", tc.entity, tc.want, string(got))
		}
	}
}
