package secret

import (
	"errors"
	"reflect"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

func TestLoad(t *testing.T) {
	friend := &Plan{
		Name:   "friend",
		Create: command.New(nil, []string{"echo", "hello", "friend"}),
	}
	dbCreds := &Plan{
		Name:   "db-creds",
		Create: command.New(nil, []string{"openssl", "rand", "-base64", "32"}),
		Plans: Plans{
			"service": &Plan{
				Name:       "service",
				Create:     command.New(nil, []string{"cp", "-f", "/dev/stdin", "/etc/enrypted-creds/$NAME/$ID.cred"}),
				Destroy:    command.New(nil, []string{"rm", "-f", "/etc/enrypted-creds/$NAME/$ID.cred"}),
				Activate:   command.New(nil, []string{"cp", "-f", "/etc/enrypted-creds/$NAME/$ID.cred", "/etc/enrypted-creds/service.cred"}),
				Deactivate: command.New(nil, []string{"rm", "-f", "/etc/enrypted-creds/service.cred"}),
			},
			"remote": &Plan{
				Name:       "remote",
				Create:     command.New(nil, []string{"ssh", "host", "-csecret-agent create $NAME $ID"}),
				Destroy:    command.New(nil, []string{"ssh", "host", "-csecret-agent destroy $NAME $ID"}),
				Activate:   command.New(nil, []string{"ssh", "host", "-csecret-agent activate $NAME $ID"}),
				Deactivate: command.New(nil, []string{"ssh", "host", "-csecret-agent deactivate $NAME $ID"}),
				Test:       command.New(nil, []string{"ssh", "host", "-csecret-agent test $NAME $ID"}),
			},
		},
	}
	tests := []struct {
		plan           string
		expectedErr    error
		expectedSecret *Secret
	}{
		{
			expectedSecret: &Secret{
				name:      "friend",
				plan:      friend,
				instances: nil,
			},
		},
		{
			expectedSecret: &Secret{
				name:      "db-creds",
				plan:      dbCreds,
				instances: nil,
			},
		},
		{
			expectedErr: nil,
			expectedSecret: &Secret{
				name:      "stale-creds",
				plan:      nil,
				instances: nil,
			},
		},
		{
			expectedErr: nil,
			expectedSecret: &Secret{
				name:      "missing-creds",
				plan:      nil,
				instances: nil,
			},
		},
	}
	for _, tc := range tests {
		t.Run("Test load secret "+tc.expectedSecret.name, func(t *testing.T) {
			secret, err := Load("./test/plans/multiple.json", tc.expectedSecret.name, nil)
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}
			if !reflect.DeepEqual(tc.expectedSecret, secret) {
				t.Errorf("expected '%v', got '%v'", tc.expectedSecret, secret)
			}
		})
	}
}
