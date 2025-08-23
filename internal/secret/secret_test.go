package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/mocks"
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
	defaultMockList := func(string) ([]string, error) {
		return nil, nil
	}
	defaultMockReadActive := func(string) (*string, bool, bool, error) {
		return nil, false, false, nil
	}
	tests := []struct {
		expectedErr    error
		expectedSecret *Secret
		mockList       func(string) ([]string, error)
		mockReadActive func(string) (*string, bool, bool, error)
		mockReads      []func(string) ([]byte, string, bool, bool, error)
	}{
		{
			expectedSecret: &Secret{
				Name:      "friend",
				Plan:      friend,
				Instances: make(Instances),
			},
			mockList:       defaultMockList,
			mockReadActive: defaultMockReadActive,
		},
		{
			expectedSecret: &Secret{
				Name:      "db-creds",
				Plan:      dbCreds,
				Instances: make(Instances),
			},
			mockList:       defaultMockList,
			mockReadActive: defaultMockReadActive,
		},
		{
			expectedErr: nil,
			expectedSecret: &Secret{
				Name:      "missing-creds",
				Plan:      nil,
				Instances: make(Instances),
			},
			mockList:       defaultMockList,
			mockReadActive: defaultMockReadActive,
		},
		{
			expectedErr: nil,
			expectedSecret: &Secret{
				Name: "stale-creds",
				Plan: nil,
				Instances: Instances{
					"instance-1": &Instance{
						Id: "instance-1",
						Plan: Plan{
							Name: "stale-creds",
						},
						Status: Creating,
					},
					"instance-2": &Instance{
						Id: "instance-2",
						Plan: Plan{
							Name: "stale-creds",
						},
						Status: Destroying,
					},
				},
			},
			mockList: func(string) ([]string, error) {
				return []string{"instance-1", "instance-2"}, nil
			},
			mockReadActive: defaultMockReadActive,
			mockReads: []func(string) ([]byte, string, bool, bool, error){
				func(id string) ([]byte, string, bool, bool, error) {
					return []byte(`{"name":"stale-creds"}`), "stale-creds", true, false, nil
				},
				func(id string) ([]byte, string, bool, bool, error) {
					return []byte(`{"name":"stale-creds"}`), "stale-creds", false, true, nil
				},
			},
		},
		{
			expectedErr: nil,
			expectedSecret: &Secret{
				Name: "db-creds",
				Plan: dbCreds,
				Instances: Instances{
					"instance-1": &Instance{
						Id: "instance-1",
						Plan: Plan{
							Name: "db-creds",
						},
						Status: Inactive,
					},
					"instance-2": &Instance{
						Id:     "instance-2",
						Plan:   *dbCreds,
						Status: Inactive,
					},
				},
			},
			mockList: func(string) ([]string, error) {
				return []string{"instance-1", "instance-2"}, nil
			},
			mockReadActive: defaultMockReadActive,
			mockReads: []func(string) ([]byte, string, bool, bool, error){
				func(id string) ([]byte, string, bool, bool, error) {
					return []byte(`{"name":"db-creds"}`), "db-creds", false, false, nil
				},
				func(id string) ([]byte, string, bool, bool, error) {
					plan, _ := json.Marshal(dbCreds)
					return plan, "db-creds", false, false, nil
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run("Test load secret "+tc.expectedSecret.Name, func(t *testing.T) {
			store := &mocks.MockStore{}
			mocks.Expect(&store.Mock, store.List, tc.mockList)
			for _, read := range tc.mockReads {
				mocks.Expect(&store.Mock, store.Read, read)
			}
			mocks.Expect(&store.Mock, store.ReadActive, tc.mockReadActive)
			secret, err := Load("./test/plans/multiple.json", tc.expectedSecret.Name, store)
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}
			secret.store = nil
			for _, instance := range secret.Instances {
				instance.store = nil
			}
			if !cmp.Equal(tc.expectedSecret, secret, cmpopts.IgnoreUnexported(Plan{}, command.Command{}, Secret{}, Instance{})) {
				diff := cmp.Diff(tc.expectedSecret, secret, cmpopts.IgnoreUnexported(Plan{}, command.Command{}, Secret{}, Instance{}))
				t.Errorf("Secret did not match: %v", diff)
			}
		})
	}
}

func TestLoadAll(t *testing.T) {
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
	defaultMockListAll := func() ([]string, error) {
		return nil, nil
	}
	tests := []struct {
		name            string
		plans           string
		expectedErr     error
		expectedSecrets Secrets
		mockListAll     func() ([]string, error)
		mockReadActives []func(string) (*string, bool, bool, error)
		mockReads       []func(string) ([]byte, string, bool, bool, error)
	}{
		{
			name:            "none",
			plans:           "empty.json",
			expectedSecrets: Secrets{},
			mockListAll:     defaultMockListAll,
		},
		{
			name:  "multiple",
			plans: "multiple.json",
			expectedSecrets: Secrets{
				"friend": &Secret{
					Name:      "friend",
					Plan:      friend,
					Instances: make(Instances),
				},
				"db-creds": &Secret{
					Name:      "db-creds",
					Plan:      dbCreds,
					Instances: make(Instances),
				},
			},
			mockListAll:     defaultMockListAll,
			mockReads:       []func(string) ([]byte, string, bool, bool, error){},
			mockReadActives: []func(string) (*string, bool, bool, error){},
		},
		{
			name:        "multiple with instances",
			plans:       "multiple.json",
			expectedErr: nil,
			expectedSecrets: Secrets{
				"friend": &Secret{
					Name:      "friend",
					Plan:      friend,
					Instances: make(Instances),
				},
				"db-creds": &Secret{
					Name: "db-creds",
					Plan: dbCreds,
					Instances: Instances{
						"instance-1": &Instance{
							Id: "instance-1",
							Plan: Plan{
								Name: "db-creds",
							},
							Status: Deactivating,
						},
						"instance-2": &Instance{
							Id:     "instance-2",
							Plan:   *dbCreds,
							Status: Inactive,
						},
					},
				},
				"stale-creds": &Secret{
					Name: "stale-creds",
					Plan: nil,
					Instances: Instances{
						"instance-3": &Instance{
							Id: "instance-3",
							Plan: Plan{
								Name: "stale-creds",
							},
							Status: Inactive,
						},
						"instance-4": &Instance{
							Id: "instance-4",
							Plan: Plan{
								Name: "stale-creds",
							},
							Status: Active,
						},
					},
				},
				"orphaned-creds": &Secret{
					Name: "orphaned-creds",
					Plan: nil,
					Instances: Instances{
						"instance-5": &Instance{
							Id: "instance-5",
							Plan: Plan{
								Name: "orphaned-creds",
							},
							Status: Activating,
						},
					},
				},
			},
			mockListAll: func() ([]string, error) {
				return []string{"instance-1", "instance-2", "instance-3", "instance-4", "instance-5"}, nil
			},
			mockReads: []func(string) ([]byte, string, bool, bool, error){
				func(id string) ([]byte, string, bool, bool, error) {
					return []byte(`{"name":"db-creds"}`), "db-creds", false, false, nil
				},
				func(id string) ([]byte, string, bool, bool, error) {
					plan, _ := json.Marshal(dbCreds)
					return plan, "db-creds", false, false, nil
				},
				func(id string) ([]byte, string, bool, bool, error) {
					return []byte(`{"name":"stale-creds"}`), "stale-creds", false, false, nil
				},
				func(id string) ([]byte, string, bool, bool, error) {
					return []byte(`{"name":"stale-creds"}`), "stale-creds", false, false, nil
				},
				func(id string) ([]byte, string, bool, bool, error) {
					return []byte(`{"name":"orphaned-creds"}`), "orphaned-creds", false, false, nil
				},
			},
			mockReadActives: []func(string) (*string, bool, bool, error){
				func(string) (*string, bool, bool, error) {
					id := "instance-1"
					return &id, false, true, nil
				},
				func(string) (*string, bool, bool, error) {
					id := "instance-4"
					return &id, false, false, nil
				},
				func(string) (*string, bool, bool, error) {
					id := "instance-5"
					return &id, true, false, nil
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run("Test load all secrets "+tc.name, func(t *testing.T) {
			store := &mocks.MockStore{}
			mocks.Expect(&store.Mock, store.ListAll, tc.mockListAll)
			for _, read := range tc.mockReads {
				mocks.Expect(&store.Mock, store.Read, read)
			}
			for _, read := range tc.mockReadActives {
				mocks.Expect(&store.Mock, store.ReadActive, read)
			}
			secrets, err := LoadAll(fmt.Sprintf("./test/plans/%v", tc.plans), store)
			if !errors.Is(err, tc.expectedErr) {
				t.Errorf("expected error '%v', got '%v'", tc.expectedErr, err)
			}
			for _, secret := range secrets {
				secret.store = nil
				for _, instance := range secret.Instances {
					instance.store = nil
				}
			}
			if !cmp.Equal(tc.expectedSecrets, secrets, cmpopts.IgnoreUnexported(Plan{}, command.Command{}, Secret{}, Instance{})) {
				diff := cmp.Diff(tc.expectedSecrets, secrets, cmpopts.IgnoreUnexported(Plan{}, command.Command{}, Secret{}, Instance{}))
				t.Errorf("Secrets did not match: %v", diff)
			}
		})
	}
}
