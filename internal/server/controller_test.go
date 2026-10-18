package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/eliasvasylenko/secret-agent/internal/auth"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/mocks"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/google/go-cmp/cmp"
)

func policyForCurrentUser(t *testing.T, roles auth.Roles) (*auth.Policy, string) {
	t.Helper()
	self, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(self.Uid, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	var loaded auth.Policy
	raw := fmt.Sprintf(`{"roles":[{"name":"binding","bindings":[{"auth":"system","uid":%d}]}]}`, uint32(n))
	if err := json.Unmarshal([]byte(raw), &loaded); err != nil {
		t.Fatal(err)
	}
	if len(roles) == 0 {
		roles = auth.Roles{
			&auth.Role{Name: "test", Permissions: auth.Permissions{auth.All: auth.Any}},
		}
	}
	binding := loaded.Roles[0].Bindings[0]
	for _, role := range roles {
		role.Bindings = auth.Bindings{binding}
	}
	return &auth.Policy{Authenticators: loaded.Authenticators, Roles: roles}, fmt.Sprintf("linux:%s/%s", self.Username, self.Uid)
}

func unixTestConn(t *testing.T) net.Conn {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	errc := make(chan error, 1)
	peer := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		peer <- conn
	}()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	select {
	case accepted := <-peer:
		t.Cleanup(func() { _ = accepted.Close() })
		return accepted
	case err := <-errc:
		t.Fatal(err)
	}
	return nil
}

func handlerWithConn(c *Controller, conn net.Conn) http.Handler {
	mux := http.NewServeMux()
	c.buildHandler(mux.Handle)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), connectionKey{}, conn)
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

type immediateHandle struct {
	inst *secrets.Instance
}

func (h immediateHandle) Wait(context.Context) (*secrets.Instance, error) {
	return h.inst, nil
}

func (h immediateHandle) Cancel(context.Context) error {
	return nil
}

type trackingHandle struct {
	inst     *secrets.Instance
	done     chan struct{}
	once     sync.Once
	canceled bool
	mu       sync.Mutex
}

func (h *trackingHandle) Wait(ctx context.Context) (*secrets.Instance, error) {
	select {
	case <-h.done:
		return h.inst, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *trackingHandle) complete() {
	h.once.Do(func() { close(h.done) })
}

func (h *trackingHandle) Cancel(context.Context) error {
	h.mu.Lock()
	h.canceled = true
	h.mu.Unlock()
	h.complete()
	return nil
}

func (h *trackingHandle) wasCanceled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.canceled
}

func newTestController(t *testing.T, agent backend.Backend) (*Controller, http.Handler, string) {
	t.Helper()
	policy, principal := policyForCurrentUser(t, nil)
	c := NewController(agent, policy, NewLimiter(0, 0))
	return c, handlerWithConn(c, unixTestConn(t)), principal
}

func expectCatalog(mockBackend *mocks.MockBackend, mockCatalog *mocks.MockCatalog) {
	mocks.Expect(&mockBackend.Mock, mockBackend.Catalog, func() backend.Catalog {
		return mockCatalog
	})
}

func readySlot(c *Controller, secretId, principal string) *attachSlot {
	slot, err := c.claimSlot(secretId, principal, attachStreamStdin)
	if err != nil {
		panic(err)
	}
	if _, err := c.claimSlot(secretId, principal, attachStreamStdout); err != nil {
		panic(err)
	}
	if _, err := c.claimSlot(secretId, principal, attachStreamStderr); err != nil {
		panic(err)
	}
	return slot
}

func startSlot(t *testing.T, c *Controller, slot *attachSlot, handle backend.Handle) {
	t.Helper()
	taken, err := c.takeSlot(slot.key.secretId, slot.key.principal)
	if err != nil {
		t.Fatal(err)
	}
	if taken != slot {
		t.Fatal("took a different slot")
	}
	slot.watch(handle)
}

func TestController_listSecrets(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockSecrets := &mocks.MockSecrets{}
	defer mockSecrets.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
	mocks.Expect(&mockSecrets.Mock, mockSecrets.List, func(ctx context.Context) (secrets.Secrets, error) {
		return secrets.Secrets{"s1": {Id: "s1", Version: 1}}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

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

func TestController_secretGrantAllowsOneSecret(t *testing.T) {
	roles := auth.Roles{
		&auth.Role{Name: "payroll", Secrets: map[string]auth.Permissions{"secret-a": {auth.All: auth.Any}}},
	}

	t.Run("list hides the other secret", func(t *testing.T) {
		mockBackend := &mocks.MockBackend{}
		defer mockBackend.Mock.Validate(t)
		mockCatalog := &mocks.MockCatalog{}
		defer mockCatalog.Mock.Validate(t)
		mockSecrets := &mocks.MockSecrets{}
		defer mockSecrets.Mock.Validate(t)
		expectCatalog(mockBackend, mockCatalog)
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
		mocks.Expect(&mockSecrets.Mock, mockSecrets.List, func(ctx context.Context) (secrets.Secrets, error) {
			return secrets.Secrets{
				"secret-a": {Id: "secret-a", Version: 1},
				"secret-b": {Id: "secret-b", Version: 1},
			}, nil
		})

		policy, _ := policyForCurrentUser(t, roles)
		c := NewController(mockBackend, policy, NewLimiter(0, 0))
		mux := handlerWithConn(c, unixTestConn(t))

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/secrets", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.Bytes())
		}
		var got ItemsResponse[secrets.Secrets]
		if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, ok := got.Items["secret-a"]; !ok {
			t.Errorf("secret-a missing: %v", got.Items)
		}
		if _, ok := got.Items["secret-b"]; ok {
			t.Errorf("secret-b visible: %v", got.Items)
		}
	})

	t.Run("read and write A, refuse B", func(t *testing.T) {
		mockBackend := &mocks.MockBackend{}
		defer mockBackend.Mock.Validate(t)
		mockCatalog := &mocks.MockCatalog{}
		defer mockCatalog.Mock.Validate(t)
		mockSecrets := &mocks.MockSecrets{}
		defer mockSecrets.Mock.Validate(t)
		expectCatalog(mockBackend, mockCatalog)
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
		mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(ctx context.Context, secretId string) (*secrets.Secret, error) {
			if secretId != "secret-a" {
				t.Errorf("Get secretId = %q", secretId)
			}
			return &secrets.Secret{Id: secretId, Version: 1}, nil
		})

		policy, _ := policyForCurrentUser(t, roles)
		c := NewController(mockBackend, policy, NewLimiter(0, 0))
		mux := handlerWithConn(c, unixTestConn(t))

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/secrets/secret-a", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("get A status = %d, want 200\n%s", rec.Code, rec.Body.Bytes())
		}

		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/secrets/secret-b", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("get B status = %d, want 403\n%s", rec.Code, rec.Body.Bytes())
		}

		rec = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://test/instances", strings.NewReader(`{"secretId":"secret-b","reason":"no"}`))
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("create B status = %d, want 403\n%s", rec.Code, rec.Body.Bytes())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "http://test/instances", strings.NewReader(`{"secretId":"secret-a","reason":"yes"}`))
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("create A status = %d, want 404 (past auth, no attach slot)\n%s", rec.Code, rec.Body.Bytes())
		}
	})

	t.Run("instance id resolves to its secret", func(t *testing.T) {
		mockBackend := &mocks.MockBackend{}
		defer mockBackend.Mock.Validate(t)
		mockCatalog := &mocks.MockCatalog{}
		defer mockCatalog.Mock.Validate(t)
		mockInstances := &mocks.MockInstances{}
		defer mockInstances.Mock.Validate(t)
		expectCatalog(mockBackend, mockCatalog)
		expectCatalog(mockBackend, mockCatalog)
		expectCatalog(mockBackend, mockCatalog)
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
		mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(ctx context.Context, instanceId string) (*secrets.Instance, error) {
			return &secrets.Instance{Id: instanceId, Secret: secrets.Secret{Id: "secret-b"}}, nil
		})
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
		mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(ctx context.Context, instanceId string) (*secrets.Instance, error) {
			return &secrets.Instance{Id: instanceId, Secret: secrets.Secret{Id: "secret-a"}}, nil
		})
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
		mocks.Expect(&mockInstances.Mock, mockInstances.List, func(ctx context.Context, secretId *string, from int, to int) (secrets.Instances, error) {
			return secrets.Instances{
				"ia": {Id: "ia", Secret: secrets.Secret{Id: "secret-a"}},
				"ib": {Id: "ib", Secret: secrets.Secret{Id: "secret-b"}},
			}, nil
		})

		policy, _ := policyForCurrentUser(t, roles)
		c := NewController(mockBackend, policy, NewLimiter(0, 0))
		mux := handlerWithConn(c, unixTestConn(t))

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/instances/ib", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("get B status = %d, want 403\n%s", rec.Code, rec.Body.Bytes())
		}

		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/instances/ia", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("get A status = %d, want 200\n%s", rec.Code, rec.Body.Bytes())
		}

		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/instances", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d, want 200\n%s", rec.Code, rec.Body.Bytes())
		}
		var got ItemsResponse[secrets.Instances]
		if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, ok := got.Items["ia"]; !ok {
			t.Errorf("instance of A missing: %v", got.Items)
		}
		if _, ok := got.Items["ib"]; ok {
			t.Errorf("instance of B visible: %v", got.Items)
		}
	})
}

func TestController_getSecret(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockSecrets := &mocks.MockSecrets{}
	defer mockSecrets.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
	mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(ctx context.Context, secretId string) (*secrets.Secret, error) {
		if secretId != "my-secret" {
			t.Errorf("Get secretId = %q", secretId)
		}
		return &secrets.Secret{Id: "my-secret"}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

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
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.List, func(ctx context.Context, secretId *string, from int, to int) (secrets.Instances, error) {
		if secretId == nil || *secretId != "sid" {
			t.Errorf("List secretId = %v", secretId)
		}
		return secrets.Instances{}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/instances?secretId=sid", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestController_listInstances_allSecrets(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.List, func(ctx context.Context, secretId *string, from int, to int) (secrets.Instances, error) {
		if secretId != nil {
			t.Errorf("List secretId = %v, want nil", *secretId)
		}
		return secrets.Instances{}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/instances", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestController_getInstance(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(ctx context.Context, instanceId string) (*secrets.Instance, error) {
		return &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/instances/i1", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestController_createInstance_requiresAttachSlot(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)

	_, mux, _ := newTestController(t, mockBackend)

	body := `{"secretId":"sid","env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/instances", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_createInstance(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockRunner := &mocks.MockRunner{}
	defer mockRunner.Mock.Validate(t)
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{OperationNumber: 1}}
	c, mux, principal := newTestController(t, mockBackend)
	mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(secretId string) backend.Runner {
		if secretId != "sid" {
			t.Errorf("Runner secretId = %q", secretId)
		}
		return mockRunner
	})
	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		ctx context.Context,
		name secrets.OperationName,
		instanceId string,
		params executor.OperationParameters,
		proposer backend.Proposer,
		stdio command.Stdio,
	) (*secrets.Instance, backend.Handle, error) {
		if name != secrets.Create || params.StartedBy != principal || params.Reason != "create-reason" {
			t.Errorf("Run name=%s StartedBy=%q Reason=%q", name, params.StartedBy, params.Reason)
		}
		return instance, immediateHandle{inst: instance}, nil
	})

	readySlot(c, "sid", principal)

	body := `{"secretId":"sid","env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/instances", bytes.NewReader([]byte(body)))
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
}

func TestController_createInstance_passesSlotStdio(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockRunner := &mocks.MockRunner{}
	defer mockRunner.Mock.Validate(t)
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "sid", Version: 1}, Status: secrets.Status{OperationNumber: 1}}
	stdinRead := make(chan struct{})
	handle := &trackingHandle{inst: instance, done: make(chan struct{})}
	var capturedStdin []byte
	mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(string) backend.Runner { return mockRunner })
	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		_ context.Context,
		_ secrets.OperationName,
		_ string,
		_ executor.OperationParameters,
		_ backend.Proposer,
		stdio command.Stdio,
	) (*secrets.Instance, backend.Handle, error) {
		go func() {
			capturedStdin, _ = io.ReadAll(stdio.Stdin)
			close(stdinRead)
			handle.complete()
		}()
		return instance, handle, nil
	})

	c, mux, principal := newTestController(t, mockBackend)
	slot := readySlot(c, "sid", principal)
	go func() {
		_, _ = slot.pipes.stdinW.Write([]byte("payload"))
		_ = slot.pipes.stdinW.Close()
	}()

	createBody := `{"secretId":"sid","env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/instances", bytes.NewReader([]byte(createBody)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}

	<-stdinRead
	if string(capturedStdin) != "payload" {
		t.Errorf("stdin = %q, want payload", capturedStdin)
	}
}

func TestController_attachSecret_rejectsMissingUpgrade(t *testing.T) {
	_, mux, _ := newTestController(t, &mocks.MockBackend{})

	attachRec := httptest.NewRecorder()
	attachReq := httptest.NewRequest(http.MethodPost, "http://test/secrets/sid/attach/stdin", nil)
	mux.ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusUpgradeRequired {
		t.Fatalf("status = %d, want 426\nbody: %s", attachRec.Code, attachRec.Body.Bytes())
	}
}

func TestController_createOperation(t *testing.T) {
	instance := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "sid", Version: 1}, Status: secrets.Status{OperationNumber: 1}}

	tests := []struct {
		name   string
		opName secrets.OperationName
		reason string
	}{
		{"activate", secrets.Activate, "act-reason"},
		{"deactivate", secrets.Deactivate, "deact-reason"},
		{"destroy", secrets.Destroy, "destroy-reason"},
		{"test", secrets.Test, "test-reason"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBackend := &mocks.MockBackend{}
			defer mockBackend.Mock.Validate(t)
			mockCatalog := &mocks.MockCatalog{}
			defer mockCatalog.Mock.Validate(t)
			mockInstances := &mocks.MockInstances{}
			defer mockInstances.Mock.Validate(t)
			mockRunner := &mocks.MockRunner{}
			defer mockRunner.Mock.Validate(t)
			expectCatalog(mockBackend, mockCatalog)
			mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
			mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(_ context.Context, instanceId string) (*secrets.Instance, error) {
				if instanceId != "i1" {
					t.Errorf("Get instanceId = %q", instanceId)
				}
				return instance, nil
			})
			mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(secretId string) backend.Runner {
				if secretId != "sid" {
					t.Errorf("Runner secretId = %q, want the instance's secret", secretId)
				}
				return mockRunner
			})
			mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
				_ context.Context,
				name secrets.OperationName,
				instanceId string,
				params executor.OperationParameters,
				_ backend.Proposer,
				_ command.Stdio,
			) (*secrets.Instance, backend.Handle, error) {
				if name != tt.opName || instanceId != "i1" || params.Reason != tt.reason {
					t.Errorf("Run name=%s instanceId=%q reason=%q", name, instanceId, params.Reason)
				}
				return instance, immediateHandle{inst: instance}, nil
			})

			c, mux, principal := newTestController(t, mockBackend)
			readySlot(c, "sid", principal)

			body := fmt.Sprintf(`{"instanceId":"i1","name":%q,"env":{},"forced":false,"reason":%q}`, tt.opName, tt.reason)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
			req.Header.Set("Content-Type", "application/json")
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
			}
		})
	}
}

func TestController_createOperation_unknownInstance(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(context.Context, string) (*secrets.Instance, error) {
		return nil, fmt.Errorf("no such instance")
	})

	c, mux, principal := newTestController(t, mockBackend)
	readySlot(c, "sid", principal)

	body := `{"instanceId":"missing","name":"activate","env":{},"forced":false,"reason":"r"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_createOperation_requiresInstanceId(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)

	_, mux, _ := newTestController(t, mockBackend)

	body := `{"name":"activate","env":{},"forced":false,"reason":"r"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_createInstance_requiresSecretId(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)

	_, mux, _ := newTestController(t, mockBackend)

	body := `{"env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/instances", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_listOperations(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockOperations := &mocks.MockOperations{}
	defer mockOperations.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Operations, func() backend.Operations { return mockOperations })
	mocks.Expect(&mockOperations.Mock, mockOperations.List, func(ctx context.Context, secretId, instanceId *string, from int, to int) ([]*secrets.Operation, error) {
		if secretId == nil || *secretId != "sid" || instanceId == nil || *instanceId != "i1" {
			t.Errorf("List secretId=%v instanceId=%v", secretId, instanceId)
		}
		return []*secrets.Operation{}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/operations?secretId=sid&instanceId=i1&from=0&to=10", nil)
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestController_getActive(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.GetActive, func(ctx context.Context, secretId string) (*secrets.Instance, error) {
		if secretId != "sid" {
			t.Errorf("GetActive secretId = %q", secretId)
		}
		return &secrets.Instance{Id: "i1"}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/secrets/sid/active", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestController_createInstance_slotNotReady(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)

	c, mux, principal := newTestController(t, mockBackend)
	if _, err := c.claimSlot("sid", principal, attachStreamStdin); err != nil {
		t.Fatal(err)
	}

	body := `{"secretId":"sid","env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/instances", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_createOperation_rejectsCreate(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)

	c, mux, principal := newTestController(t, mockBackend)
	readySlot(c, "sid", principal)

	body := `{"instanceId":"i1","name":"create","env":{},"forced":false,"reason":"nope"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestAttachSlot_stdinEOFDoesNotCancel(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	slot := readySlot(c, "sid", principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1"}, done: make(chan struct{})}
	startSlot(t, c, slot, handle)

	c.attachFinished(slot, attachStreamStdin, nil)
	if handle.wasCanceled() {
		t.Fatal("stdin EOF canceled the op")
	}
	handle.complete()
}

func TestAttachSlot_stdoutDisconnectCancels(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	slot := readySlot(c, "sid", principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1"}, done: make(chan struct{})}
	startSlot(t, c, slot, handle)

	c.attachFinished(slot, attachStreamStdout, nil)
	<-handle.done
	if !handle.wasCanceled() {
		t.Fatal("stdout disconnect did not cancel the op")
	}
}

func TestController_takenSlotAllowsNextAttach(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	active := readySlot(c, "sid", principal)
	taken, err := c.takeSlot("sid", principal)
	if err != nil {
		t.Fatal(err)
	}
	if taken != active {
		t.Fatal("takeSlot returned a different slot")
	}

	next, err := c.claimSlot("sid", principal, attachStreamStdin)
	if err != nil {
		t.Fatal(err)
	}
	if next == active {
		t.Fatal("new attach reused the active slot")
	}
}

func TestController_attachThenCreate_stdinReachesRun(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockRunner := &mocks.MockRunner{}
	defer mockRunner.Mock.Validate(t)
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "sid"}, Status: secrets.Status{OperationNumber: 1}}
	stdinRead := make(chan struct{})
	handle := &trackingHandle{inst: instance, done: make(chan struct{})}
	var capturedStdin []byte
	mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(string) backend.Runner { return mockRunner })
	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		_ context.Context,
		_ secrets.OperationName,
		_ string,
		_ executor.OperationParameters,
		_ backend.Proposer,
		stdio command.Stdio,
	) (*secrets.Instance, backend.Handle, error) {
		go func() {
			capturedStdin, _ = io.ReadAll(stdio.Stdin)
			close(stdinRead)
			handle.complete()
		}()
		return instance, handle, nil
	})

	_, mux, _ := newTestController(t, mockBackend)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	stdoutConn := upgradeAttach(t, server.URL, "sid", "stdout", "")
	t.Cleanup(func() { _ = stdoutConn.Close() })
	stderrConn := upgradeAttach(t, server.URL, "sid", "stderr", "")
	t.Cleanup(func() { _ = stderrConn.Close() })
	stdinConn := upgradeAttach(t, server.URL, "sid", "stdin", "")
	t.Cleanup(func() { _ = stdinConn.Close() })

	go io.Copy(io.Discard, stdoutConn)
	go io.Copy(io.Discard, stderrConn)

	resp, err := http.Post(server.URL+"/instances", "application/json", strings.NewReader(`{"secretId":"sid","reason":"create-reason"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d, want 200\nbody: %s", resp.StatusCode, body)
	}

	if _, err := stdinConn.Write([]byte("payload")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := stdinConn.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	<-stdinRead
	if string(capturedStdin) != "payload" {
		t.Errorf("stdin = %q, want payload", capturedStdin)
	}
}

func upgradeAttach(t *testing.T, serverURL, secretId, stream, body string) net.Conn {
	t.Helper()
	host := strings.TrimPrefix(serverURL, "http://")
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf(
		"POST /secrets/%s/attach/%s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nContent-Length: %d\r\n\r\n%s",
		secretId, stream, host, AttachUpgradeProtocol, len(body), body,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("attach %s status = %d, want 101", stream, resp.StatusCode)
	}
	return conn
}
