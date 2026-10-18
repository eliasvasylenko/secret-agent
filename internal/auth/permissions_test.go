package auth

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestPermissions_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Permissions
		wantErr string
	}{
		{
			name: "valid",
			raw:  `{"secrets":"read","instances":"list","all":"any"}`,
			want: Permissions{Secrets: Read, Instances: List, All: Any},
		},
		{
			name:    "invalid subject",
			raw:     `{"nope":"read"}`,
			wantErr: `invalid subject "nope"`,
		},
		{
			name:    "invalid action",
			raw:     `{"secrets":"nope"}`,
			wantErr: `invalid action "nope"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got Permissions
			err := json.Unmarshal([]byte(tc.raw), &got)
			if tc.wantErr != "" {
				if fmt.Sprint(err) != tc.wantErr {
					t.Fatalf("Unmarshal = %v, want %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("permissions = %v, want %v", got, tc.want)
			}
			for subject, action := range tc.want {
				if got[subject] != action {
					t.Errorf("%s = %q, want %q", subject, got[subject], action)
				}
			}
		})
	}
}
