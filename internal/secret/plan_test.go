package secret

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
)

func TestLoadPlans(t *testing.T) {
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
		file          string
		expectedErr   error
		expectedPlans Plans
	}{
		{
			file: "simple",
			expectedPlans: Plans{
				"friend": friend,
			},
		},
		{
			file: "complex",
			expectedPlans: Plans{
				"db-creds": dbCreds,
			},
		},
		{
			file:        "multiple",
			expectedErr: nil,
			expectedPlans: Plans{
				"friend":   friend,
				"db-creds": dbCreds,
			},
		},
		{
			file:          "missing",
			expectedErr:   fs.ErrNotExist,
			expectedPlans: Plans{},
		},
	}
	for _, tc := range tests {
		t.Run("Test load "+tc.file+" plans", func(t *testing.T) {
			plans, err := LoadPlans(fmt.Sprintf("./test/plans/%v.json", tc.file))
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}
			if !reflect.DeepEqual(tc.expectedPlans, plans) {
				t.Errorf("expected '%v', got '%v'", tc.expectedPlans, plans)
			}
		})
	}
}
