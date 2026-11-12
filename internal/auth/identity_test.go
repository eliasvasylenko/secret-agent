package auth

import (
	"fmt"
	"testing"
)

func TestCheckPermission(t *testing.T) {
	admin := &Role{Name: "admin", Permissions: Permissions{All: Any}}
	reader := &Role{Name: "reader", Permissions: Permissions{Secrets: Read, Instances: Read}}
	payroll := &Role{Name: "payroll", Secrets: map[string]Permissions{"secret-a": {All: Any}}}
	mixed := &Role{
		Name:        "mixed",
		Permissions: Permissions{Secrets: List},
		Secrets:     map[string]Permissions{"secret-a": {Secrets: Write}},
	}

	tests := []struct {
		name        string
		roles       Roles
		permissions Permissions
		secretID    string
		want        bool
	}{
		{"no roles", nil, Permissions{Secrets: Read}, "s", false},
		{"global any allows a secret", Roles{admin}, Permissions{Secrets: Write}, "s", true},
		{"global any allows an empty secret", Roles{admin}, Permissions{Secrets: Read}, "", true},
		{"read does not allow write", Roles{reader}, Permissions{Secrets: Write}, "s", false},
		{"read does not allow list", Roles{reader}, Permissions{Secrets: List}, "s", false},
		{"all read allows secrets read", Roles{&Role{Name: "audit", Permissions: Permissions{All: Read}}}, Permissions{Secrets: Read}, "s", true},
		{"subject any allows that action", Roles{&Role{Name: "ops", Permissions: Permissions{Secrets: Any}}}, Permissions{Secrets: Write}, "s", true},
		{"per-secret grant", Roles{payroll}, Permissions{Secrets: Write}, "secret-a", true},
		{"per-secret grant does not cover another secret", Roles{payroll}, Permissions{Secrets: Read}, "secret-b", false},
		{"empty secret matches a per-secret grant", Roles{payroll}, Permissions{All: Any}, "", true},
		{"empty secret does not match a different action", Roles{&Role{Name: "payroll", Secrets: map[string]Permissions{"secret-a": {Secrets: Write}}}}, Permissions{Secrets: Read}, "", false},
		{"every subject is required", Roles{reader}, Permissions{Secrets: Read, Instances: Write}, "s", false},
		{"every subject granted", Roles{reader}, Permissions{Secrets: Read, Instances: Read}, "s", true},
		{"one of two roles", Roles{reader, payroll}, Permissions{Secrets: Write}, "secret-a", true},
		{"global list still applies to another secret", Roles{mixed}, Permissions{Secrets: List}, "secret-b", true},
		{"per-secret write does not leak", Roles{mixed}, Permissions{Secrets: Write}, "secret-b", false},
		{"per-secret write applies", Roles{mixed}, Permissions{Secrets: Write}, "secret-a", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := Identity{Roles: tc.roles}
			if got := id.CheckPermission(tc.permissions, tc.secretID); got != tc.want {
				t.Errorf("CheckPermission = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAssertPermission(t *testing.T) {
	id := Identity{Roles: Roles{&Role{Name: "reader", Permissions: Permissions{Secrets: Read}}}}
	if err := id.AssertPermission(Permissions{Secrets: Read}, "s"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	err := id.AssertPermission(Permissions{Secrets: Write}, "s")
	if fmt.Sprint(err) != "operation not permitted with roles [reader]" {
		t.Fatalf("unexpected error: %v", err)
	}

	err = Identity{}.AssertPermission(Permissions{Secrets: Read}, "")
	if fmt.Sprint(err) != "operation not permitted with roles []" {
		t.Fatalf("unexpected error: %v", err)
	}
}
