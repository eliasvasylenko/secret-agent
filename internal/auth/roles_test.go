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
			got := role.Permissions.matches(tc.subject, tc.action)
			if got != tc.permitted {
				t.Errorf("matches(%s, %s): expected %v, got %v", tc.subject, tc.action, tc.permitted, got)
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
		bound     RoleNames
		perms     Permissions
		permitted bool
	}{
		{RoleNames{"reader"}, Permissions{Secrets: Read}, true},
		{RoleNames{"reader"}, Permissions{Secrets: Write}, false},
		{RoleNames{"admin"}, Permissions{Secrets: Write}, true},
		{RoleNames{"reader", "admin"}, Permissions{Instances: Write}, true},
		{RoleNames{"reader"}, Permissions{Instances: Read}, false},
	}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			got := roles.CheckPermission(tc.bound, tc.perms, "")
			if got != tc.permitted {
				t.Errorf("CheckPermission(%v, %v): expected %v, got %v", tc.bound, tc.perms, tc.permitted, got)
			}
		})
	}
}

func TestRolesAssertPermission(t *testing.T) {
	roles := Roles{
		"reader": {Name: "reader", Permissions: Permissions{Secrets: Read}},
	}
	if err := roles.AssertPermission(RoleNames{"reader"}, Permissions{Secrets: Read}, ""); err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if err := roles.AssertPermission(RoleNames{"reader"}, Permissions{Secrets: Write}, ""); err == nil {
		t.Error("expected error for denied permission")
	}
}

func TestSecretGrants(t *testing.T) {
	roles := Roles{
		"payroll": {
			Name: "payroll",
			Secrets: map[string]Permissions{
				"secret-a": {All: Any},
				"secret-c": {Secrets: Read},
				"secret-d": {Secrets: Write, Instances: Write},
			},
		},
		"write-only": {
			Name:    "write-only",
			Secrets: map[string]Permissions{"secret-d": {Instances: Write}},
		},
		"admin": {
			Name:        "admin",
			Permissions: Permissions{All: Any},
		},
		"split": {
			Name:        "split",
			Permissions: Permissions{Secrets: Write},
			Secrets:     map[string]Permissions{"secret-a": {Instances: Write}},
		},
		"reader-plus": {
			Name:        "reader-plus",
			Permissions: Permissions{Secrets: Read, All: Any},
			Secrets:     map[string]Permissions{"secret-a": {Instances: Write}},
		},
	}

	payroll := RoleNames{"payroll"}
	tests := []struct {
		name      string
		bound     RoleNames
		perms     Permissions
		secretID  string
		permitted bool
	}{
		{"any covers read and write on A", payroll, Permissions{Secrets: Read}, "secret-a", true},
		{"any covers instance write on A", payroll, Permissions{Instances: Write}, "secret-a", true},
		{"any covers both writes required to operate", payroll, Permissions{Secrets: Write, Instances: Write}, "secret-a", true},
		{"A does not cover B", payroll, Permissions{Secrets: Read}, "secret-b", false},
		{"read does not grant write", payroll, Permissions{Instances: Write}, "secret-c", false},
		{"secrets read does not cover instances", payroll, Permissions{Instances: Read}, "secret-c", false},
		{"write on both subjects covers an operation", payroll, Permissions{Secrets: Write, Instances: Write}, "secret-d", true},
		{"write does not grant read", payroll, Permissions{Secrets: Read}, "secret-d", false},
		{"global admin covers an unlisted secret", RoleNames{"admin"}, Permissions{Secrets: Write}, "secret-b", true},
		{"global and per-secret together cover an operation", RoleNames{"split"}, Permissions{Secrets: Write, Instances: Write}, "secret-a", true},
		{"per-secret half does not apply to another secret", RoleNames{"split"}, Permissions{Secrets: Write, Instances: Write}, "secret-b", false},
		{"all still matches when the subject action does not", RoleNames{"reader-plus"}, Permissions{Secrets: Write}, "secret-b", true},
		{"collection allows a named grant", payroll, Permissions{Secrets: List}, "", true},
		{"collection refuses when no grant matches", RoleNames{"write-only"}, Permissions{Secrets: List}, "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := roles.CheckPermission(tc.bound, tc.perms, tc.secretID)
			if got != tc.permitted {
				t.Errorf("CheckPermission(%v, %v, %q) = %v, want %v", tc.bound, tc.perms, tc.secretID, got, tc.permitted)
			}
		})
	}
}

func TestSecretGrantsJSON(t *testing.T) {
	raw := []byte(`{"payroll":{"permissions":{},"secrets":{"secret-a":{"all":"any","instances":"read"}}}}`)
	var roles Roles
	if err := json.Unmarshal(raw, &roles); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cmp.Equal(roles["payroll"].Secrets["secret-a"], Permissions{All: Any, Instances: Read}) {
		t.Fatalf("secrets = %v", roles["payroll"].Secrets)
	}
	encoded, err := json.Marshal(roles)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var again Roles
	if err := json.Unmarshal(encoded, &again); err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if diff := cmp.Diff(roles, again); diff != "" {
		t.Errorf("round trip:\n%s", diff)
	}

	if err := json.Unmarshal([]byte(`{"payroll":{"permissions":{"secrets":"explode"}}}`), &roles); err == nil {
		t.Fatal("expected invalid global action to fail")
	}
	if err := json.Unmarshal([]byte(`{"payroll":{"secrets":{"secret-a":{"nope":"read"}}}}`), &roles); err == nil {
		t.Fatal("expected invalid per-secret subject to fail")
	}
}

func TestRoleNamesUnmarshalJSON(t *testing.T) {
	tests := []struct {
		json string
		want RoleNames
	}{
		{`"admin"`, RoleNames{"admin"}},
		{`["admin","reader"]`, RoleNames{"admin", "reader"}},
	}
	for _, tc := range tests {
		var got RoleNames
		if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
			t.Errorf("Unmarshal(%s): %v", tc.json, err)
			continue
		}
		if !cmp.Equal(got, tc.want) {
			t.Errorf("Unmarshal(%s):\n%s", tc.json, cmp.Diff(tc.want, got))
		}
	}
}
