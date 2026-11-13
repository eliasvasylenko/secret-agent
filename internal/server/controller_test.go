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
	"time"

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
	return &auth.Policy{Authenticators: loaded.Authenticators, Roles: roles}, fmt.Sprintf("%s/%s@system", self.Username, self.Uid)
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
	c := NewController(agent, policy, NewLimiter(0, 0), 0, 0)
	return c, handlerWithConn(c, unixTestConn(t)), principal
}

func expectNoParents(t *testing.T, mockBackend *mocks.MockBackend) {
	t.Helper()
	mockCatalog := &mocks.MockCatalog{}
	t.Cleanup(func() { mockCatalog.Mock.Validate(t) })
	mockSecrets := &mocks.MockSecrets{}
	t.Cleanup(func() { mockSecrets.Mock.Validate(t) })
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
	mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(context.Context, string) (*secrets.Secret, error) {
		return &secrets.Secret{Version: 1}, nil
	})
}

// expectSecretGets is expectNoParents for flows that look the secret up n times
// (for example create, then the start gate).
func expectSecretGets(t *testing.T, mockBackend *mocks.MockBackend, n int) {
	t.Helper()
	mockCatalog := &mocks.MockCatalog{}
	t.Cleanup(func() { mockCatalog.Mock.Validate(t) })
	mockSecrets := &mocks.MockSecrets{}
	t.Cleanup(func() { mockSecrets.Mock.Validate(t) })
	for i := 0; i < n; i++ {
		expectCatalog(mockBackend, mockCatalog)
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
		mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(context.Context, string) (*secrets.Secret, error) {
			return &secrets.Secret{Version: 1}, nil
		})
	}
}

func expectCatalog(mockBackend *mocks.MockBackend, mockCatalog *mocks.MockCatalog) {
	mocks.Expect(&mockBackend.Mock, mockBackend.Catalog, func() backend.Catalog {
		return mockCatalog
	})
}

func newPendingOp(c *Controller, principal string) *operationEntry {
	entry := newOperationEntry(principal, "sid", "", secrets.Create, executor.OperationParameters{}, c.leases)
	c.operations.add(entry)
	return entry
}

func readyOp(c *Controller, principal string) *operationEntry {
	entry := newPendingOp(c, principal)
	attachAllClaims(c, entry.id(), principal)
	return entry
}

func attachAllClaims(c *Controller, operationId, principal string) {
	entry, err := c.operations.get(operationId)
	if err != nil {
		panic(err)
	}
	for fd := 0; fd <= 2; fd++ {
		mode := command.Write
		if fd == 0 {
			mode = command.Read
		}
		if _, err := entry.claimAttach(principal, []int{fd}, mode); err != nil {
			panic(err)
		}
	}
}

func beginOp(t *testing.T, c *Controller, entry *operationEntry, handle backend.Handle) {
	t.Helper()
	if err := entry.start(); err != nil {
		t.Fatal(err)
	}
	c.operations.watch(entry, handle)
}

// eventually polls until check passes or the deadline is hit.
func eventually(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(time.Millisecond)
	}
}

func postCreate(t *testing.T, mux http.Handler, body string) (string, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201\nbody: %s", rec.Code, rec.Body.Bytes())
	}
	var created OperationCreatedResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return created.OperationID, rec
}

func postStart(t *testing.T, mux http.Handler, operationId string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations/"+operationId+"/start", nil)
	mux.ServeHTTP(rec, req)
	return rec
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
		c := NewController(mockBackend, policy, NewLimiter(0, 0), 0, 0)
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
		expectCatalog(mockBackend, mockCatalog)
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
		mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(ctx context.Context, secretId string) (*secrets.Secret, error) {
			if secretId != "secret-b" {
				t.Errorf("Get secretId = %q", secretId)
			}
			return &secrets.Secret{Id: secretId, Version: 1}, nil
		})
		expectCatalog(mockBackend, mockCatalog)
		mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
		mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(ctx context.Context, secretId string) (*secrets.Secret, error) {
			if secretId != "secret-a" {
				t.Errorf("Get secretId = %q", secretId)
			}
			return &secrets.Secret{Id: secretId, Version: 1}, nil
		})

		policy, _ := policyForCurrentUser(t, roles)
		c := NewController(mockBackend, policy, NewLimiter(0, 0), 0, 0)
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
		req := httptest.NewRequest(http.MethodPost, "http://test/operations", strings.NewReader(`{"secretId":"secret-b","name":"create","reason":"no"}`))
		req.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create B status = %d, want 201 (creation runs nothing; the gate is at start)\n%s", rec.Code, rec.Body.Bytes())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "http://test/operations", strings.NewReader(`{"secretId":"secret-a","name":"create","reason":"yes"}`))
		req.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create A status = %d, want 201 (pending operation)\n%s", rec.Code, rec.Body.Bytes())
		}
	})

	t.Run("permission without the parent role is refused at start", func(t *testing.T) {
		mockBackend := &mocks.MockBackend{}
		defer mockBackend.Mock.Validate(t)
		mockCatalog := &mocks.MockCatalog{}
		defer mockCatalog.Mock.Validate(t)
		mockSecrets := &mocks.MockSecrets{}
		defer mockSecrets.Mock.Validate(t)
		for i := 0; i < 2; i++ {
			expectCatalog(mockBackend, mockCatalog)
			mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
			mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(ctx context.Context, secretId string) (*secrets.Secret, error) {
				return &secrets.Secret{Id: secretId, Version: 1, Parents: []secrets.Parent{"other"}}, nil
			})
		}

		policy, _ := policyForCurrentUser(t, nil)
		c := NewController(mockBackend, policy, NewLimiter(0, 0), 0, 0)
		mux := handlerWithConn(c, unixTestConn(t))

		operationId, _ := postCreate(t, mux, `{"secretId":"secret-b","name":"create","reason":"no"}`)
		rec := postStart(t, mux, operationId)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403\n%s", rec.Code, rec.Body.Bytes())
		}
		if !strings.Contains(rec.Body.String(), "operation not permitted") {
			t.Fatalf("body = %s", rec.Body.Bytes())
		}
	})

	t.Run("parent without permission cannot start", func(t *testing.T) {
		mockBackend := &mocks.MockBackend{}
		defer mockBackend.Mock.Validate(t)
		mockCatalog := &mocks.MockCatalog{}
		defer mockCatalog.Mock.Validate(t)
		mockSecrets := &mocks.MockSecrets{}
		defer mockSecrets.Mock.Validate(t)
		for i := 0; i < 2; i++ {
			expectCatalog(mockBackend, mockCatalog)
			mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
			mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(ctx context.Context, secretId string) (*secrets.Secret, error) {
				return &secrets.Secret{Id: secretId, Version: 1, Parents: []secrets.Parent{"payroll"}}, nil
			})
		}

		policy, _ := policyForCurrentUser(t, roles)
		c := NewController(mockBackend, policy, NewLimiter(0, 0), 0, 0)
		mux := handlerWithConn(c, unixTestConn(t))

		operationId, _ := postCreate(t, mux, `{"secretId":"secret-b","name":"create","reason":"propose"}`)
		rec := postStart(t, mux, operationId)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403\n%s", rec.Code, rec.Body.Bytes())
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
		c := NewController(mockBackend, policy, NewLimiter(0, 0), 0, 0)
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

func TestController_getSecret_notFound(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockSecrets := &mocks.MockSecrets{}
	defer mockSecrets.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
	mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(context.Context, string) (*secrets.Secret, error) {
		return nil, &backend.SecretNotFoundError{SecretId: "missing"}
	})

	_, mux, _ := newTestController(t, mockBackend)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/secrets/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_getSecret_unexpected(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockSecrets := &mocks.MockSecrets{}
	defer mockSecrets.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Secrets, func() backend.Secrets { return mockSecrets })
	mocks.Expect(&mockSecrets.Mock, mockSecrets.Get, func(context.Context, string) (*secrets.Secret, error) {
		return nil, fmt.Errorf("disk full")
	})

	_, mux, _ := newTestController(t, mockBackend)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/secrets/my-secret", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500\nbody: %s", rec.Code, rec.Body.Bytes())
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
		if from != 0 || to != 10 {
			t.Errorf("List from=%d to=%d, want 0 10", from, to)
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
		if from != 0 || to != 10 {
			t.Errorf("List from=%d to=%d, want 0 10", from, to)
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

func TestController_listInstances_explicitRange(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.List, func(ctx context.Context, secretId *string, from int, to int) (secrets.Instances, error) {
		if from != 2 || to != 5 {
			t.Errorf("List from=%d to=%d, want 2 5", from, to)
		}
		return secrets.Instances{}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/instances?from=2&to=5", nil)
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

func TestController_getInstance_notFound(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(context.Context, string) (*secrets.Instance, error) {
		return nil, &backend.InstanceNotFoundError{InstanceId: "missing"}
	})

	_, mux, _ := newTestController(t, mockBackend)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/instances/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_startOperation_allowsNoAttach(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockRunner := &mocks.MockRunner{}
	defer mockRunner.Mock.Validate(t)
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Revision: 1}
	expectSecretGets(t, mockBackend, 2)
	mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(string) backend.Runner { return mockRunner })
	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		_ context.Context,
		_ secrets.OperationName,
		_ string,
		_ executor.OperationParameters,
		_ backend.Proposer,
		files command.Files,
	) (*secrets.Instance, backend.Handle, error) {
		if len(files.Fds) != 0 {
			t.Errorf("files.Fds = %v, want none attached", files.Fds)
		}
		return instance, immediateHandle{inst: instance}, nil
	})

	_, mux, _ := newTestController(t, mockBackend)

	operationId, _ := postCreate(t, mux, `{"secretId":"sid","name":"create","env":{},"forced":false,"reason":"create-reason"}`)
	rec := postStart(t, mux, operationId)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_startOperation_domainErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code int
	}{
		{"conflict", &backend.InstanceAlreadyActiveError{Operation: secrets.Activate, ActiveId: "i1"}, http.StatusConflict},
		{"invalid", &backend.ReasonTooLongError{Length: 10, Max: 8}, http.StatusBadRequest},
		{"unclassified", fmt.Errorf("disk full"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBackend := &mocks.MockBackend{}
			defer mockBackend.Mock.Validate(t)
			mockRunner := &mocks.MockRunner{}
			defer mockRunner.Mock.Validate(t)
			expectSecretGets(t, mockBackend, 2)
			mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(string) backend.Runner { return mockRunner })
			mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
				context.Context,
				secrets.OperationName,
				string,
				executor.OperationParameters,
				backend.Proposer,
				command.Files,
			) (*secrets.Instance, backend.Handle, error) {
				return nil, nil, tt.err
			})

			_, mux, _ := newTestController(t, mockBackend)
			operationId, _ := postCreate(t, mux, `{"secretId":"sid","name":"create","env":{},"forced":false,"reason":"create-reason"}`)
			rec := postStart(t, mux, operationId)
			if rec.Code != tt.code {
				t.Fatalf("status = %d, want %d\nbody: %s", rec.Code, tt.code, rec.Body.Bytes())
			}
		})
	}
}

func TestController_createAndStartOperation(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockRunner := &mocks.MockRunner{}
	defer mockRunner.Mock.Validate(t)
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Revision: 1}
	c, mux, principal := newTestController(t, mockBackend)
	expectSecretGets(t, mockBackend, 2)
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
		stdio command.Files,
	) (*secrets.Instance, backend.Handle, error) {
		if name != secrets.Create || params.StartedBy != principal || params.Reason != "create-reason" {
			t.Errorf("Run name=%s StartedBy=%q Reason=%q", name, params.StartedBy, params.Reason)
		}
		return instance, immediateHandle{inst: instance}, nil
	})

	operationId, _ := postCreate(t, mux, `{"secretId":"sid","name":"create","env":{},"forced":false,"reason":"create-reason"}`)
	attachAllClaims(c, operationId, principal)

	rec := postStart(t, mux, operationId)
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

func TestController_startOperation_passesAttachedFiles(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockRunner := &mocks.MockRunner{}
	defer mockRunner.Mock.Validate(t)
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "sid", Version: 1}, Revision: 1}
	stdinRead := make(chan struct{})
	handle := &trackingHandle{inst: instance, done: make(chan struct{})}
	var capturedStdin []byte
	expectNoParents(t, mockBackend)
	mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(string) backend.Runner { return mockRunner })
	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		_ context.Context,
		_ secrets.OperationName,
		_ string,
		_ executor.OperationParameters,
		_ backend.Proposer,
		stdio command.Files,
	) (*secrets.Instance, backend.Handle, error) {
		go func() {
			capturedStdin, _ = io.ReadAll(stdio.Fds[0])
			close(stdinRead)
			handle.complete()
		}()
		return instance, handle, nil
	})

	c, mux, principal := newTestController(t, mockBackend)
	entry := readyOp(c, principal)
	go func() {
		peer := entry.byFd[0].peer
		_, _ = peer.Write([]byte("payload"))
		_ = peer.Close()
	}()

	rec := postStart(t, mux, entry.id())
	if rec.Code != http.StatusOK {
		t.Fatalf("start status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}

	<-stdinRead
	if string(capturedStdin) != "payload" {
		t.Errorf("stdin = %q, want payload", capturedStdin)
	}
}

func TestController_attachOperation_rejectsMissingUpgrade(t *testing.T) {
	_, mux, _ := newTestController(t, &mocks.MockBackend{})

	attachRec := httptest.NewRecorder()
	attachReq := httptest.NewRequest(http.MethodPost, "http://test/operations/op1/attach", nil)
	mux.ServeHTTP(attachRec, attachReq)
	if attachRec.Code != http.StatusUpgradeRequired {
		t.Fatalf("status = %d, want 426\nbody: %s", attachRec.Code, attachRec.Body.Bytes())
	}
}

func TestController_createOperation(t *testing.T) {
	instance := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "sid", Version: 1}, Revision: 1}

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
			expectSecretGets(t, mockBackend, 1)
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
				_ command.Files,
			) (*secrets.Instance, backend.Handle, error) {
				if name != tt.opName || instanceId != "i1" || params.Reason != tt.reason {
					t.Errorf("Run name=%s instanceId=%q reason=%q", name, instanceId, params.Reason)
				}
				return instance, immediateHandle{inst: instance}, nil
			})

			c, mux, principal := newTestController(t, mockBackend)

			body := fmt.Sprintf(`{"instanceId":"i1","name":%q,"env":{},"forced":false,"reason":%q}`, tt.opName, tt.reason)
			operationId, _ := postCreate(t, mux, body)
			attachAllClaims(c, operationId, principal)

			rec := postStart(t, mux, operationId)
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
		return nil, &backend.InstanceNotFoundError{InstanceId: "missing"}
	})

	_, mux, _ := newTestController(t, mockBackend)

	body := `{"instanceId":"missing","name":"activate","env":{},"forced":false,"reason":"r"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_createOperation_instanceLookupFailure(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockCatalog := &mocks.MockCatalog{}
	defer mockCatalog.Mock.Validate(t)
	mockInstances := &mocks.MockInstances{}
	defer mockInstances.Mock.Validate(t)
	expectCatalog(mockBackend, mockCatalog)
	mocks.Expect(&mockCatalog.Mock, mockCatalog.Instances, func() backend.Instances { return mockInstances })
	mocks.Expect(&mockInstances.Mock, mockInstances.Get, func(context.Context, string) (*secrets.Instance, error) {
		return nil, fmt.Errorf("disk full")
	})

	_, mux, _ := newTestController(t, mockBackend)

	body := `{"instanceId":"missing","name":"activate","env":{},"forced":false,"reason":"r"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500\nbody: %s", rec.Code, rec.Body.Bytes())
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

func TestController_createOperation_requiresSecretIdForCreate(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)

	_, mux, _ := newTestController(t, mockBackend)

	body := `{"name":"create","env":{},"forced":false,"reason":"create-reason"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_finishedOperationExpires(t *testing.T) {
	policy, principal := policyForCurrentUser(t, nil)
	c := NewController(&mocks.MockBackend{}, policy, NewLimiter(0, 0), time.Hour, 5*time.Millisecond)
	mux := handlerWithConn(c, unixTestConn(t))

	entry := readyOp(c, principal)
	beginOp(t, c, entry, immediateHandle{inst: &secrets.Instance{Id: "i1"}})

	getStatus := func() int {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/operations/"+entry.id(), nil))
		return rec.Code
	}
	eventually(t, time.Second, func() bool { return getStatus() == http.StatusNotFound })
	if _, err := c.operations.get(entry.id()); err == nil {
		t.Fatal("expired entry still registered")
	}
}

func TestController_pendingOperationExpires(t *testing.T) {
	policy, principal := policyForCurrentUser(t, nil)
	c := NewController(&mocks.MockBackend{}, policy, NewLimiter(0, 0), 5*time.Millisecond, time.Hour)

	entry := newPendingOp(c, principal)
	eventually(t, time.Second, func() bool {
		_, err := c.operations.get(entry.id())
		return err != nil
	})
	if err := entry.start(); err == nil {
		t.Fatal("expired entry could be started")
	}
}

func TestController_startedOperationDoesNotExpire(t *testing.T) {
	policy, principal := policyForCurrentUser(t, nil)
	c := NewController(&mocks.MockBackend{}, policy, NewLimiter(0, 0), 5*time.Millisecond, time.Hour)

	entry := readyOp(c, principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1"}, done: make(chan struct{})}
	beginOp(t, c, entry, handle)
	time.Sleep(20 * time.Millisecond)
	if _, err := c.operations.get(entry.id()); err != nil {
		t.Fatal("started entry expired")
	}
	handle.complete()
}

func TestController_createOperation_rejectsMissingContentType(t *testing.T) {
	_, mux, _ := newTestController(t, &mocks.MockBackend{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", strings.NewReader(`{"secretId":"sid","name":"create","reason":"r"}`))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_attachOperation_rejectsMissingContentType(t *testing.T) {
	c, mux, principal := newTestController(t, &mocks.MockBackend{})
	entry := newPendingOp(c, principal)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations/"+entry.id()+"/attach", strings.NewReader(`{"fds":[0],"mode":"r"}`))
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", AttachUpgradeProtocol)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_getOperation_rejectsBadUntilDone(t *testing.T) {
	c, mux, principal := newTestController(t, &mocks.MockBackend{})
	entry := newPendingOp(c, principal)
	for _, query := range []string{"untilDone=yes", "untilDone=-1s"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://test/operations/"+entry.id()+"?"+query, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400\nbody: %s", query, rec.Code, rec.Body.Bytes())
		}
	}
}

func TestController_startOperation_afterDeleteNotFound(t *testing.T) {
	c, mux, principal := newTestController(t, &mocks.MockBackend{})
	entry := readyOp(c, principal)
	if err := c.operations.cancel(entry); err != nil {
		t.Fatal(err)
	}
	if _, err := c.operations.get(entry.id()); err == nil {
		t.Fatal("cancelled entry still registered")
	}

	rec := postStart(t, mux, entry.id())
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404\nbody: %s", rec.Code, rec.Body.Bytes())
	}
	// A stale pointer cannot transition the closed entry either.
	if err := entry.start(); err == nil {
		t.Fatal("closed entry could be started")
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

func TestController_startOperation_allowsPartialAttach(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	entry := newPendingOp(c, principal)
	if _, err := entry.claimAttach(principal, []int{0}, command.Read); err != nil {
		t.Fatal(err)
	}
	if err := entry.start(); err != nil {
		t.Fatalf("start with only fd 0 attached: %v", err)
	}
}

func TestController_createOperation_rejectsCreateWithInstance(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)

	_, mux, _ := newTestController(t, mockBackend)

	body := `{"secretId":"sid","instanceId":"i1","name":"create","env":{},"forced":false,"reason":"nope"}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://test/operations", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestPendingOperation_stdinEOFDoesNotCancel(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	op := readyOp(c, principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1"}, done: make(chan struct{})}
	beginOp(t, c, op, handle)

	c.operations.attachEnded(op, op.byFd[0])
	if _, err := c.operations.get(op.id()); err != nil {
		t.Fatal("stdin EOF closed a started op")
	}
	if handle.wasCanceled() {
		t.Fatal("stdin EOF canceled the op")
	}
	handle.complete()
}

func TestPendingOperation_stdoutDisconnectCancels(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	op := readyOp(c, principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1"}, done: make(chan struct{})}
	beginOp(t, c, op, handle)

	c.operations.attachEnded(op, op.byFd[1])
	<-handle.done
	if !handle.wasCanceled() {
		t.Fatal("stdout disconnect did not cancel the op")
	}
}

func TestPendingOperation_twoPendingCoexist(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	first := readyOp(c, principal)
	second := readyOp(c, principal)
	if first == second || first.id() == second.id() {
		t.Fatal("pending operations are not distinct")
	}
}

func TestController_attachThenStart_stdinReachesRun(t *testing.T) {
	mockBackend := &mocks.MockBackend{}
	defer mockBackend.Mock.Validate(t)
	mockRunner := &mocks.MockRunner{}
	defer mockRunner.Mock.Validate(t)
	instance := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "sid"}, Revision: 1}
	stdinRead := make(chan struct{})
	handle := &trackingHandle{inst: instance, done: make(chan struct{})}
	var capturedStdin []byte
	expectSecretGets(t, mockBackend, 2)
	mocks.Expect(&mockBackend.Mock, mockBackend.Runner, func(string) backend.Runner { return mockRunner })
	mocks.Expect(&mockRunner.Mock, mockRunner.Run, func(
		_ context.Context,
		_ secrets.OperationName,
		_ string,
		_ executor.OperationParameters,
		_ backend.Proposer,
		stdio command.Files,
	) (*secrets.Instance, backend.Handle, error) {
		go func() {
			capturedStdin, _ = io.ReadAll(stdio.Fds[0])
			close(stdinRead)
			handle.complete()
		}()
		return instance, handle, nil
	})

	_, mux, _ := newTestController(t, mockBackend)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	createResp, err := http.Post(server.URL+"/operations", "application/json", strings.NewReader(`{"secretId":"sid","name":"create","reason":"create-reason"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createResp.Body)
		t.Fatalf("create status = %d, want 201\nbody: %s", createResp.StatusCode, body)
	}
	var created OperationCreatedResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	stdoutConn := upgradeAttach(t, server.URL, created.OperationID, 1)
	t.Cleanup(func() { _ = stdoutConn.Close() })
	stderrConn := upgradeAttach(t, server.URL, created.OperationID, 2)
	t.Cleanup(func() { _ = stderrConn.Close() })
	stdinConn := upgradeAttach(t, server.URL, created.OperationID, 0)
	t.Cleanup(func() { _ = stdinConn.Close() })
	if _, err := stdinConn.Write([]byte("pre-")); err != nil {
		t.Fatalf("write stdin head: %v", err)
	}

	go io.Copy(io.Discard, stdoutConn)
	go io.Copy(io.Discard, stderrConn)

	resp, err := http.Post(server.URL+"/operations/"+created.OperationID+"/start", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("start status = %d, want 200\nbody: %s", resp.StatusCode, body)
	}

	if _, err := stdinConn.Write([]byte("payload")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := stdinConn.Close(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	<-stdinRead
	if string(capturedStdin) != "pre-payload" {
		t.Errorf("stdin = %q, want pre-payload", capturedStdin)
	}
}

func upgradeAttach(t *testing.T, serverURL, operationId string, fd int) net.Conn {
	t.Helper()
	host := strings.TrimPrefix(serverURL, "http://")
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	mode := command.Write
	if fd == 0 {
		mode = command.Read
	}
	body, err := json.Marshal(AttachRequest{Fds: []int{fd}, Mode: mode})
	if err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf(
		"POST /operations/%s/attach HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		operationId, host, AttachUpgradeProtocol, len(body), body,
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
		t.Fatalf("attach fd %d status = %d, want 101", fd, resp.StatusCode)
	}
	return conn
}

func TestClaimAttach_sharedOutputIsOneFile(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	entry := newPendingOp(c, principal)
	if _, err := entry.claimAttach(principal, []int{1, 2}, command.Write); err != nil {
		t.Fatal(err)
	}
	if _, err := entry.claimAttach(principal, []int{0}, command.Read); err != nil {
		t.Fatal(err)
	}
	in := entry.byFd[0]
	out := entry.byFd[1]
	errOut := entry.byFd[2]
	if out.process != errOut.process {
		t.Fatal("stdout and stderr do not share a file")
	}
	if in.process == out.process {
		t.Fatal("stdin was joined onto the output file")
	}

	if _, err := out.process.Write([]byte("both")); err != nil {
		t.Fatal(err)
	}
	_ = out.process.Close()
	got, err := io.ReadAll(out.peer)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "both" {
		t.Fatalf("output = %q", got)
	}
}

func TestClaimAttach_extraDescriptorKeepsItsNumber(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	entry := newPendingOp(c, principal)
	attachAllClaims(c, entry.id(), principal)
	att, err := entry.claimAttach(principal, []int{5}, command.Read)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.claimAttach(principal, []int{5}, command.Read); err == nil {
		t.Fatal("fd 5 claimed twice")
	}

	files := entry.files()
	if len(files.Fds) != 6 {
		t.Fatalf("files.Fds = %d entries, want 6", len(files.Fds))
	}
	if files.Fds[5] != att.process {
		t.Fatal("fd 5 does not carry the extra attachment")
	}
	if files.Fds[3] != nil || files.Fds[4] != nil {
		t.Fatal("descriptor gap was not left empty")
	}
	if files.Tty != command.NoTty {
		t.Fatalf("files.Tty = %d, want NoTty", files.Tty)
	}
}

func TestClaimAttach_cttyOnExtraDescriptor(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	entry := newPendingOp(c, principal)
	attachAllClaims(c, entry.id(), principal)
	att, err := entry.claimAttach(principal, []int{5}, command.Ctty)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(att.close)
	if _, err := entry.claimAttach(principal, []int{6}, command.Ctty); err == nil {
		t.Fatal("controlling terminal claimed twice")
	}

	files := entry.files()
	if files.Tty != 5 {
		t.Fatalf("files.Tty = %d, want 5", files.Tty)
	}
	if files.Fds[5] != att.process {
		t.Fatal("fd 5 does not carry the controlling terminal")
	}
}

func TestClaimAttach_terminalIsOneFile(t *testing.T) {
	c, _, principal := newTestController(t, &mocks.MockBackend{})
	entry := newPendingOp(c, principal)
	att, err := entry.claimAttach(principal, []int{0, 1, 2}, command.Ctty)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(att.close)
	in := entry.byFd[0]
	out := entry.byFd[1]
	errOut := entry.byFd[2]
	if in.process != out.process || out.process != errOut.process {
		t.Fatal("terminal descriptors do not share a file")
	}
	if !command.Terminal(in.process) {
		t.Fatal("process file is not a terminal")
	}
	if files := entry.files(); files.Tty != 0 {
		t.Fatalf("files.Tty = %d, want 0", files.Tty)
	}
}

func TestController_deleteOperation_cancelsStarted(t *testing.T) {
	c, mux, principal := newTestController(t, &mocks.MockBackend{})
	op := readyOp(c, principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1"}, done: make(chan struct{})}
	beginOp(t, c, op, handle)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "http://test/operations/"+op.id(), nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204\nbody: %s", rec.Code, rec.Body.Bytes())
	}
	<-handle.done
	if !handle.wasCanceled() {
		t.Fatal("started operation was not cancelled")
	}
}

func TestController_getOperation_wait(t *testing.T) {
	c, mux, principal := newTestController(t, &mocks.MockBackend{})
	op := readyOp(c, principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1", Operation: secrets.Operation{}}, done: make(chan struct{})}
	beginOp(t, c, op, handle)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "http://test/operations/"+op.id()+"?untilDone=1s", nil)
		mux.ServeHTTP(rec, req)
		done <- rec
	}()

	select {
	case rec := <-done:
		t.Fatalf("wait returned before the operation finished: %d %s", rec.Code, rec.Body.Bytes())
	case <-time.After(20 * time.Millisecond):
	}

	handle.complete()
	rec := <-done
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}
}

func TestController_getOperation_untilDoneExpires(t *testing.T) {
	c, mux, principal := newTestController(t, &mocks.MockBackend{})
	op := readyOp(c, principal)
	handle := &trackingHandle{inst: &secrets.Instance{Id: "i1", Operation: secrets.Operation{}}, done: make(chan struct{})}
	beginOp(t, c, op, handle)
	defer handle.complete()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://test/operations/"+op.id()+"?untilDone=20ms", nil)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\nbody: %s", rec.Code, rec.Body.Bytes())
	}
	var status OperationStatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.State != string(operationStarted) {
		t.Fatalf("state = %s, want started", status.State)
	}
}
