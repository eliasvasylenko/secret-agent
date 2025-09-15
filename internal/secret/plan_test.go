package secret

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLoadPlans(t *testing.T) {
	friend := &Plan{
		Name:   "friend",
		Create: command.New("echo hello friend", nil, ""),
	}
	dbCreds := &Plan{
		Name:   "db-creds",
		Create: command.New("openssl rand -base64 32", nil, ""),
		Plans: Plans{
			"service": &Plan{
				Name:       "service",
				Create:     command.New("cat > /etc/enrypted-creds/$NAME/$ID.cred", nil, ""),
				Destroy:    command.New("rm -f /etc/enrypted-creds/$NAME/$ID.cred", nil, ""),
				Activate:   command.New("cp -f /etc/enrypted-creds/$NAME/$ID.cred /etc/enrypted-creds/service.cred", nil, ""),
				Deactivate: command.New("rm -f /etc/enrypted-creds/service.cred", nil, ""),
			},
			"remote": &Plan{
				Name:       "remote",
				Create:     command.New("ssh host -csecret-agent create $NAME $ID", nil, ""),
				Destroy:    command.New("ssh host -csecret-agent destroy $NAME $ID", nil, ""),
				Activate:   command.New("ssh host -csecret-agent activate $NAME $ID", nil, ""),
				Deactivate: command.New("ssh host -csecret-agent deactivate $NAME $ID", nil, ""),
				Test:       command.New("ssh host -csecret-agent test $NAME $ID", nil, ""),
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
			if !cmp.Equal(tc.expectedPlans, plans, cmpopts.IgnoreUnexported(Plan{}, command.Command{})) {
				diff := cmp.Diff(tc.expectedPlans, plans, cmpopts.IgnoreUnexported(Plan{}, command.Command{}))
				t.Errorf("Plans did not match: %v", diff)
			}
		})
	}
}
