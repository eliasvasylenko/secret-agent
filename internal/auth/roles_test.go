package auth

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRoleCheckPermission(t *testing.T) {
	role := Role{
		Name: "reader",
		Permissions: Permissions{
			Secrets: Read,
			All:     List,
		},
	}
	tests := []struct {
		subject   Subject
		action    Action
		permitted bool
	}{
		{Secrets, Read, true},
		{Secrets, Write, false},
		{All, List, true},
		{Instances, Read, false},
	}
	for _, tc := range tests {
		t.Run(string(tc.subject)+"_"+string(tc.action), func(t *testing.T) {
			got := role.CheckPermission(tc.subject, tc.action)
			if got != tc.permitted {
				t.Errorf("CheckPermission(%s, %s): expected %v, got %v", tc.subject, tc.action, tc.permitted, got)
			}
		})
	}
}

func TestRolesCheckPermission(t *testing.T) {
	roles := Roles{
		"reader": {
			Name:        "reader",
			Permissions: Permissions{Secrets: Read},
		},
		"admin": {
			Name:        "admin",
			Permissions: Permissions{All: Any},
		},
	}
	tests := []struct {
		claims    ClaimedRoles
		perms     Permissions
		permitted bool
	}{
		{ClaimedRoles{"reader"}, Permissions{Secrets: Read}, true},
		{ClaimedRoles{"reader"}, Permissions{Secrets: Write}, false},
		{ClaimedRoles{"admin"}, Permissions{Secrets: Write}, true},
		{ClaimedRoles{"reader", "admin"}, Permissions{Instances: Write}, true},
		{ClaimedRoles{"reader"}, Permissions{Instances: Read}, false},
	}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			got := roles.CheckPermission(tc.claims, tc.perms)
			if got != tc.permitted {
				t.Errorf("CheckPermission(%v, %v): expected %v, got %v", tc.claims, tc.perms, tc.permitted, got)
			}
		})
	}
}

func TestRolesAssertPermission(t *testing.T) {
	roles := Roles{
		"reader": {Name: "reader", Permissions: Permissions{Secrets: Read}},
	}
	if err := roles.AssertPermission(ClaimedRoles{"reader"}, Permissions{Secrets: Read}); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := roles.AssertPermission(ClaimedRoles{"reader"}, Permissions{Secrets: Write}); err == nil {
		t.Error("expected error for denied permission")
	}
}

func TestClaimedRolesUnmarshalJSON(t *testing.T) {
	tests := []struct {
		json string
		want ClaimedRoles
	}{
		{`"admin"`, ClaimedRoles{"admin"}},
		{`["admin","reader"]`, ClaimedRoles{"admin", "reader"}},
	}
	for _, tc := range tests {
		var got ClaimedRoles
		if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
			t.Errorf("Unmarshal(%s): %v", tc.json, err)
			continue
		}
		if !cmp.Equal(got, tc.want) {
			t.Errorf("Unmarshal(%s):\n%s", tc.json, cmp.Diff(tc.want, got))
		}
	}
}
