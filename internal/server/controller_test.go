package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
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

// expectStoreInstances registers two Instances lookups: one for the HTTP handler
// and one for trackOperation's background await goroutine.
func expectStoreInstances(mockStore *mocks.MockSecrets, mockInstances *mocks.MockInstances) {
	fn := func(secretId string) store.Instances { return mockInstances }
	mocks.Expect(&mockStore.Mock, mockStore.Instances, fn)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, fn)
}

func expectOperationAwait(mockInstances *mocks.MockInstances, mockOperations *mocks.MockOperations, execDone chan struct{}, instance *secrets.Instance, await func(context.Context, int) (store.Event, *secrets.Instance, error)) {
	mocks.Expect(&mockInstances.Mock, mockInstances.Operations, func(instanceId string) store.Operations {
		return mockOperations
	})
	if await == nil {
		await = func(context.Context, int) (store.Event, *secrets.Instance, error) {
			if execDone != nil {
				defer close(execDone)
			}
			return store.NewCompletedEvent("", executor.OperationParameters{}), instance, nil
		}
	}
	mocks.Expect(&mockOperations.Mock, mockOperations.Await, await)
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

func newTestController(t *testing.T, store store.Store, identity *auth.Identity) (*Controller, *http.ServeMux) {
	t.Helper()
	c := NewController(store, noopLimiter{}, noopPermissions{identity: identity}, 5*time.Minute)
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
	mockOperations := &mocks.MockOperations{}
	defer mockOperations.Mock.Validate(t)
	expectStoreInstances(mockStore, mockInstances)
	execDone := make(chan struct{})
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}
	mocks.Expect(&mockInstances.Mock, mockInstances.Create, func(ctx context.Context, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
		if params.StartedBy != "test-user" {
			t.Errorf("StartedBy = %q", params.StartedBy)
		}
		if params.Reason != "create-reason" {
			t.Errorf("Reason = %q", params.Reason)
		}
		return instance, nil
	})
	expectOperationAwait(mockInstances, mockOperations, execDone, instance, nil)

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
	<-execDone
}

func TestController_attachProcess_stdinReachesSubprocess(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mockOperations := &mocks.MockOperations{}
	defer mockOperations.Mock.Validate(t)
	expectStoreInstances(mockStore, mockInstances)
	execDone := make(chan struct{})
	stdinRead := make(chan struct{})
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "sid", Version: 1}, Status: secrets.Status{OperationNumber: 1}}
	var capturedStdin []byte
	mocks.Expect(&mockInstances.Mock, mockInstances.Create, func(ctx context.Context, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
		go func() {
			capturedStdin, _ = io.ReadAll(stdio.Stdin)
			close(stdinRead)
		}()
		return instance, nil
	})
	expectOperationAwait(mockInstances, mockOperations, execDone, instance, func(context.Context, int) (store.Event, *secrets.Instance, error) {
		<-stdinRead
		defer close(execDone)
		return store.NewCompletedEvent("", executor.OperationParameters{}), instance, nil
	})

	_, mux := newTestController(t, mockStore, &auth.Identity{Principal: "test-user"})
	server := httptest.NewServer(mux)
	defer server.Close()

	createBody := `{"env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/secrets/sid/instances", bytes.NewReader([]byte(createBody)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}

	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatalf("dial attach server: %v", err)
	}

	host := strings.TrimPrefix(server.URL, "http://")
	attachPath := "/secrets/sid/instances/new-id/operations/1/attach/stdin"
	payload := "payload"
	attachReq := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nContent-Length: %d\r\n\r\n%s",
		attachPath,
		host,
		AttachUpgradeProtocol,
		len(payload),
		payload,
	)
	if _, err := conn.Write([]byte(attachReq)); err != nil {
		t.Fatalf("write attach request: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close attach conn: %v", err)
	}

	<-execDone
	if string(capturedStdin) != "payload" {
		t.Errorf("stdin = %q, want payload", capturedStdin)
	}
}

func TestController_attachProcess_rejectsMissingUpgrade(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mockOperations := &mocks.MockOperations{}
	defer mockOperations.Mock.Validate(t)
	expectStoreInstances(mockStore, mockInstances)
	execDone := make(chan struct{})
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "sid", Version: 1}, Status: secrets.Status{OperationNumber: 1}}
	mocks.Expect(&mockInstances.Mock, mockInstances.Create, func(context.Context, executor.OperationParameters, command.Stdio) (*secrets.Instance, error) {
		return instance, nil
	})
	expectOperationAwait(mockInstances, mockOperations, execDone, instance, nil)

	_, mux := newTestController(t, mockStore, &auth.Identity{Principal: "test-user"})

	createBody := `{"env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/secrets/sid/instances", bytes.NewReader([]byte(createBody)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200", rec.Code)
	}

	attachRec := httptest.NewRecorder()
	attachReq := httptest.NewRequest(http.MethodPost, "http://test/secrets/sid/instances/new-id/operations/1/attach/stdin", nil)
	mux.ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusUpgradeRequired {
		t.Fatalf("status = %d, want 426\nbody: %s", attachRec.Code, attachRec.Body.Bytes())
	}
	<-execDone
}

func TestController_createOperation(t *testing.T) {
	instance := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}

	tests := []struct {
		name   string
		opName secrets.OperationName
		reason string
		expect func(*mocks.MockInstances, *mocks.MockOperations, string, chan struct{})
	}{
		{
			name:   "activate",
			opName: secrets.Activate,
			reason: "act-reason",
			expect: func(m *mocks.MockInstances, o *mocks.MockOperations, reason string, execDone chan struct{}) {
				mocks.Expect(&m.Mock, m.Activate, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" || params.Reason != reason {
						t.Errorf("Activate instanceId=%q reason=%q", instanceId, params.Reason)
					}
					return instance, nil
				})
				expectOperationAwait(m, o, execDone, instance, nil)
			},
		},
		{
			name:   "deactivate",
			opName: secrets.Deactivate,
			reason: "deact-reason",
			expect: func(m *mocks.MockInstances, o *mocks.MockOperations, reason string, execDone chan struct{}) {
				mocks.Expect(&m.Mock, m.Deactivate, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" || params.Reason != reason {
						t.Errorf("Deactivate instanceId=%q reason=%q", instanceId, params.Reason)
					}
					return instance, nil
				})
				expectOperationAwait(m, o, execDone, instance, nil)
			},
		},
		{
			name:   "destroy",
			opName: secrets.Destroy,
			reason: "destroy-reason",
			expect: func(m *mocks.MockInstances, o *mocks.MockOperations, reason string, execDone chan struct{}) {
				mocks.Expect(&m.Mock, m.Destroy, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" || params.Reason != reason {
						t.Errorf("Destroy instanceId=%q reason=%q", instanceId, params.Reason)
					}
					return instance, nil
				})
				expectOperationAwait(m, o, execDone, instance, nil)
			},
		},
		{
			name:   "test",
			opName: secrets.Test,
			reason: "test-reason",
			expect: func(m *mocks.MockInstances, o *mocks.MockOperations, reason string, execDone chan struct{}) {
				mocks.Expect(&m.Mock, m.Test, func(ctx context.Context, instanceId string, params executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
					if instanceId != "i1" || params.Reason != reason {
						t.Errorf("Test instanceId=%q reason=%q", instanceId, params.Reason)
					}
					return instance, nil
				})
				expectOperationAwait(m, o, execDone, instance, nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := &mocks.MockSecrets{}
			defer mockStore.Mock.Validate(t)
			mockInstances := &mocks.MockInstances{}
			defer mockInstances.Mock.Validate(t)
			mockOperations := &mocks.MockOperations{}
			defer mockOperations.Mock.Validate(t)
			expectStoreInstances(mockStore, mockInstances)
			execDone := make(chan struct{})
			tt.expect(mockInstances, mockOperations, tt.reason, execDone)

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
			<-execDone
		})
	}
}

func TestController_getOperations(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mockOperations := &mocks.MockOperations{}
	defer mockOperations.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		return mockInstances
	})
	mocks.Expect(&mockInstances.Mock, mockInstances.Operations, func(instanceId string) store.Operations {
		if instanceId != "i1" {
			t.Errorf("Operations instanceId=%s", instanceId)
		}
		return mockOperations
	})
	mocks.Expect(&mockOperations.Mock, mockOperations.List, func(ctx context.Context, from int, to int) ([]*secrets.Operation, error) {
		if from != 0 || to != 10 {
			t.Errorf("List from=%d to=%d", from, to)
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

func TestController_operationResult_withoutTrackedOperation(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mockOperations := &mocks.MockOperations{}
	defer mockOperations.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		return mockInstances
	})
	instance := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "sid", Version: 1}, Status: secrets.Status{OperationNumber: 1}}
	mocks.Expect(&mockInstances.Mock, mockInstances.Operations, func(instanceId string) store.Operations {
		return mockOperations
	})
	mocks.Expect(&mockOperations.Mock, mockOperations.Await, func(ctx context.Context, opNumber int) (store.Event, *secrets.Instance, error) {
		return store.NewCompletedEvent("", executor.OperationParameters{}), instance, nil
	})

	_, mux := newTestController(t, mockStore, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets/sid/instances/i1/operations/1/result", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_operationResult(t *testing.T) {
	mockStore := &mocks.MockSecrets{}
	defer mockStore.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	mockOperations := &mocks.MockOperations{}
	defer mockOperations.Mock.Validate(t)
	mocks.Expect(&mockStore.Mock, mockStore.Instances, func(secretId string) store.Instances {
		return mockInstances
	})
	instance := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "sid", Version: 1}, Status: secrets.Status{OperationNumber: 1}}
	mocks.Expect(&mockInstances.Mock, mockInstances.Operations, func(instanceId string) store.Operations {
		if instanceId != "i1" {
			t.Errorf("Operations instanceId=%q", instanceId)
		}
		return mockOperations
	})
	mocks.Expect(&mockOperations.Mock, mockOperations.Await, func(ctx context.Context, opNumber int) (store.Event, *secrets.Instance, error) {
		if opNumber != 1 {
			t.Errorf("Await opNumber=%d", opNumber)
		}
		return store.NewCompletedEvent("", executor.OperationParameters{}), instance, nil
	})

	c, mux := newTestController(t, mockStore, nil)
	key := operationMapKey{secretId: "sid", instanceId: "i1", operationNumber: 1}
	done := make(chan struct{})
	close(done)
	c.operations.Store(key, &operation{done: done})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets/sid/instances/i1/operations/1/result", nil)
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
}
