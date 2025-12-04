package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestLoadPlans(t *testing.T) {
	friend := &Secret{
		Id:     "friend",
		Create: command.New("echo hello friend", nil, ""),
	}
	dbCreds := &Secret{
		Id:     "db-creds",
		Create: command.New("openssl rand -base64 32", nil, ""),
		Derive: Secrets{
			"service": &Secret{
				Id:         "service",
				Create:     command.New("cat > /etc/enrypted-creds/$NAME/$ID.cred", nil, ""),
				Destroy:    command.New("rm -f /etc/enrypted-creds/$NAME/$ID.cred", nil, ""),
				Activate:   command.New("cp -f /etc/enrypted-creds/$NAME/$ID.cred /etc/enrypted-creds/service.cred", nil, ""),
				Deactivate: command.New("rm -f /etc/enrypted-creds/service.cred", nil, ""),
			},
			"remote": &Secret{
				Id:         "remote",
				Create:     command.New("ssh host -csecret-agent create $NAME $ID", nil, ""),
				Destroy:    command.New("ssh host -csecret-agent destroy $NAME $ID", nil, ""),
				Activate:   command.New("ssh host -csecret-agent activate $NAME $ID", nil, ""),
				Deactivate: command.New("ssh host -csecret-agent deactivate $NAME $ID", nil, ""),
				Test:       command.New("ssh host -csecret-agent test $NAME $ID", nil, ""),
			},
		},
	}
	tests := []struct {
		file            string
		expectedErr     error
		expectedSecrets Secrets
	}{
		{
			file: "simple",
			expectedSecrets: Secrets{
				"friend": friend,
			},
		},
		{
			file: "complex",
			expectedSecrets: Secrets{
				"db-creds": dbCreds,
			},
		},
		{
			file:        "multiple",
			expectedErr: nil,
			expectedSecrets: Secrets{
				"friend":   friend,
				"db-creds": dbCreds,
			},
		},
	}
	for _, tc := range tests {
		t.Run("Test load "+tc.file+" plans", func(t *testing.T) {
			secretsBytes, err := os.ReadFile(fmt.Sprintf("./test/secrets/%v.json", tc.file))
			if err != nil {
				t.Error(err)
				return
			}
			var secrets Secrets
			err = json.Unmarshal(secretsBytes, &secrets)
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}
			if !cmp.Equal(tc.expectedSecrets, secrets, cmpopts.IgnoreUnexported(Secret{}, command.Command{})) {
				diff := cmp.Diff(tc.expectedSecrets, secrets, cmpopts.IgnoreUnexported(Secret{}, command.Command{}))
				t.Errorf("Plans did not match: %v", diff)
			}
		})
	}
}
