package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/mocks"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/store"
	"github.com/google/go-cmp/cmp"
)

// noopLimiter and noopPermissions allow testing controller handlers without rate limiting or auth.
type noopLimiter struct{}

func (noopLimiter) Middleware(_ func(*http.Request) string, next http.Handler) http.Handler {
	return next
}

type noopPermissions struct {
	identity *auth.Identity
}

func (p noopPermissions) Middleware(_ auth.Permissions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.identity != nil {
			r = r.WithContext(context.WithValue(r.Context(), identityKey{}, p.identity))
		}
		next.ServeHTTP(w, r)
	})
}

func newTestController(t *testing.T, store store.Secrets, identity *auth.Identity) (*Controller, *http.ServeMux) {
	t.Helper()
	c := NewController(store, noopLimiter{}, noopPermissions{identity: identity}, 1024, 5*time.Minute)
	mux := http.NewServeMux()
	c.buildHandler(mux.Handle)
	return c, mux
}

func TestController_listSecrets(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.List, func(ctx context.Context) (secrets.Secrets, error) {
		return secrets.Secrets{"s1": {Id: "s1", Version: 1}}, nil
	})

	_, mux := newTestController(t, mockStore, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var got ItemsResponse[secrets.Secrets]
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := ItemsResponse[secrets.Secrets]{Items: secrets.Secrets{"s1": {Id: "s1", Version: 1}}}
	if !cmp.Equal(got, want, cmp.AllowUnexported(secrets.Secret{})) {
		t.Errorf("response:\n%s", cmp.Diff(want, got, cmp.AllowUnexported(secrets.Secret{})))
	}
}

func TestController_getSecret(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Get, func(ctx context.Context, secretId string) (*secrets.Secret, error) {
		if secretId != "my-secret" {
			t.Errorf("Get secretId = %q", secretId)
		}
		return &secrets.Secret{Id: "my-secret"}, nil
	})

	_, mux := newTestController(t, mockStore, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets/my-secret", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var got secrets.Secret
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Id != "my-secret" {
		t.Errorf("secret id = %q", got.Id)
	}
}

func TestController_listInstances(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		if secretId != "sid" {
			t.Errorf("Instances secretId = %q", secretId)
		}
		return mockInstances
	})
	mocks.Expect(&mockInstances.Mock, mockInstances.List, func(ctx context.Context, from int, to int) (secrets.Instances, error) {
		return secrets.Instances{}, nil
	})

	_, mux := newTestController(t, mockStore, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets/sid/instances", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var got ItemsResponse[secrets.Instances]
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Items) != 0 {
		t.Errorf("items = %v", got.Items)
	}
}

func TestController_getInstance(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		return mockInstances
	})
	mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(ctx context.Context, instanceId string) (*secrets.Instance, error) {
		if instanceId != "i1" {
			t.Errorf("Get instanceId = %q", instanceId)
		}
		return &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}, nil
	})

	_, mux := newTestController(t, mockStore, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets/sid/instances/i1", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var got secrets.Instance
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Id != "i1" {
		t.Errorf("instance id = %q", got.Id)
	}
}

func TestController_createInstance(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		return mockInstances
	})
	mocks.Expect(&mockInstances.Mock, mockInstances.Create, func(ctx context.Context, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
		if params.StartedBy != "test-user" {
			t.Errorf("StartedBy = %q", params.StartedBy)
		}
		if params.Reason != "create-reason" {
			t.Errorf("Reason = %q", params.Reason)
		}
		return &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}, nil
	})
	awaitDone := make(chan struct{})
	mocks.Expect(&mockInstances.Mock, mockInstances.Await, func(ctx context.Context, instanceId string, opNumber int) (*secrets.Instance, error) {
		defer close(awaitDone)
		return &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}, nil
	})

	_, mux := newTestController(t, mockStore, &auth.Identity{Principal: "test-user"})

	body := `{"env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/secrets/sid/instances", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}
	var got secrets.Instance
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Id != "new-id" {
		t.Errorf("instance id = %q", got.Id)
	}
	<-awaitDone
}

func TestController_createInstance_JSONInputReachesStdio(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		return mockInstances
	})
	mocks.Expect(&mockInstances.Mock, mockInstances.Create, func(ctx context.Context, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
		if stdio.Stdin != "payload-from-json" {
			t.Errorf("Create stdio.Stdin = %q, want payload-from-json", stdio.Stdin)
		}
		return &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}, nil
	})
	awaitDone := make(chan struct{})
	mocks.Expect(&mockInstances.Mock, mockInstances.Await, func(ctx context.Context, instanceId string, opNumber int) (*secrets.Instance, error) {
		defer close(awaitDone)
		return &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}, nil
	})

	_, mux := newTestController(t, mockStore, &auth.Identity{Principal: "test-user"})

	body := `{"env":{},"forced":false,"reason":"create-reason","input":"payload-from-json"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/secrets/sid/instances", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}
	<-awaitDone
}

func TestController_createOperation(t *testing.T) {
	instance := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}

	tests := []struct {
		name   string
		opName secrets.OperationName
		reason string
		expect func(*mocks.MockInstances, string)
	}{
		{
			name:   "activate",
			opName: secrets.Activate,
			reason: "act-reason",
			expect: func(m *mocks.MockInstances, reason string) {
				mocks.Expect(&m.Mock, m.Activate, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" {
						t.Errorf("Activate instanceId = %q", instanceId)
					}
					if params.Reason != reason {
						t.Errorf("Reason = %q", params.Reason)
					}
					return instance, nil
				})
			},
		},
		{
			name:   "deactivate",
			opName: secrets.Deactivate,
			reason: "deact-reason",
			expect: func(m *mocks.MockInstances, reason string) {
				mocks.Expect(&m.Mock, m.Deactivate, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" {
						t.Errorf("Deactivate instanceId = %q", instanceId)
					}
					if params.Reason != reason {
						t.Errorf("Reason = %q", params.Reason)
					}
					return instance, nil
				})
			},
		},
		{
			name:   "destroy",
			opName: secrets.Destroy,
			reason: "destroy-reason",
			expect: func(m *mocks.MockInstances, reason string) {
				mocks.Expect(&m.Mock, m.Destroy, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" {
						t.Errorf("Destroy instanceId = %q", instanceId)
					}
					if params.Reason != reason {
						t.Errorf("Reason = %q", params.Reason)
					}
					return instance, nil
				})
			},
		},
		{
			name:   "test",
			opName: secrets.Test,
			reason: "test-reason",
			expect: func(m *mocks.MockInstances, reason string) {
				mocks.Expect(&m.Mock, m.Test, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" {
						t.Errorf("Test instanceId = %q", instanceId)
					}
					if params.Reason != reason {
						t.Errorf("Reason = %q", params.Reason)
					}
					return instance, nil
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &mocks.MockSecrets{}
			defer mockStore.Mock.Validate(t)
			mockInstances := &mocks.MockInstances{}
			defer mockInstances.Mock.Validate(t)
			mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
				return mockInstances
			})
			tt.expect(mockInstances, tt.reason)
			awaitDone := make(chan struct{})
			mocks.Expect(&mockInstances.Mock, mockInstances.Await, func(ctx context.Context, instanceId string, opNumber int) (*secrets.Instance, error) {
				defer close(awaitDone)
				return instance, nil
			})

			_, mux := newTestController(t, mockStore, &auth.Identity{Principal: "op-user"})

			body := fmt.Sprintf(`{"name":%q,"env":{},"forced":false,"reason":%q}`, tt.opName, tt.reason)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://test/secrets/sid/instances/i1/operations", bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
			}
			var got secrets.Instance
			if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.Id != "i1" {
				t.Errorf("instance id = %q", got.Id)
			}
			<-awaitDone
		})
	}
}

func TestController_getOperations(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		return mockInstances
	})
	mocks.Expect(&mockInstances.Mock, mockInstances.History, func(ctx context.Context, instanceId string, from int, to int) ([]*secrets.Operation, error) {
		if instanceId != "i1" || from != 0 || to != 10 {
			t.Errorf("History instanceId=%s from=%d to=%d", instanceId, from, to)
		}
		return []*secrets.Operation{}, nil
	})

	_, mux := newTestController(t, mockStore, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets/sid/instances/i1/operations?from=0&to=10", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	var got []*secrets.Operation
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("operations = %v", got)
	}
}
