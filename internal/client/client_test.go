package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// Ensure that *InstanceClient satisfies the backend.Instances interface.
var _ backend.Instances = (*InstanceClient)(nil)

// cmp options for comparing secrets types that contain unexported fields.
var cmpSecretOpts = cmp.Options{
	cmpopts.IgnoreUnexported(secrets.Secret{}, command.Command{}),
}
var cmpInstanceOpts = cmp.Options{
	cmpopts.IgnoreUnexported(secrets.Secret{}, command.Command{}),
	cmpopts.IgnoreUnexported(time.Time{}),
}

// stubClient implements httpClient. Attach streams use a separate unix dial path.
type stubClient struct {
	status       int
	body         string
	resultStatus int
	resultBody   string
	doErr        error
	lastReq      atomic.Pointer[http.Request]
}

func (s *stubClient) Do(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "/result") {
		status := s.resultStatus
		body := s.resultBody
		if status == 0 {
			status = 408
			body = `{"error":{"status":408,"message":"timeout"}}`
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		}, nil
	}
	first := s.lastReq.CompareAndSwap(nil, req)
	if !first {
		return nil, fmt.Errorf("stub: unexpected request %s %s", req.Method, req.URL.Path)
	}
	if s.doErr != nil {
		return nil, s.doErr
	}
	return &http.Response{
		StatusCode: s.status,
		Body:       io.NopCloser(bytes.NewReader([]byte(s.body))),
	}, nil
}

// requestString returns a deterministic string representation of the request for comparison.
// Go's encoding/json uses struct field order and sorts map keys, so client request bodies are deterministic.
func requestString(req *http.Request) string {
	if req == nil {
		return ""
	}
	body, _ := io.ReadAll(req.Body)
	return req.Method + " " + req.URL.RequestURI() + "\n" + string(body)
}

func TestBuildRequest(t *testing.T) {
	ctx := context.Background()
	t.Run("no body", func(t *testing.T) {
		req, err := BuildRequest(ctx, http.MethodGet, "/secrets", nil)
		if err != nil {
			t.Fatal(err)
		}
		got := requestString(req)
		want := "GET /secrets\n"
		if got != want {
			t.Errorf("request:\n%s", cmp.Diff(want, got))
		}
	})
	t.Run("with body", func(t *testing.T) {
		body := map[string]string{"name": "create"}
		req, err := BuildRequest(ctx, http.MethodPost, "/secrets/s1/instances", body)
		if err != nil {
			t.Fatal(err)
		}
		got := requestString(req)
		want := "POST /secrets/s1/instances\n" + `{"name":"create"}` + "\n"
		if got != want {
			t.Errorf("request:\n%s", cmp.Diff(want, got))
		}
	})
}

func TestDo_success(t *testing.T) {
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/secrets", nil)
	stub := &stubClient{status: 200, body: `{"items":[{"id":"s1","version":1}]}`}
	got, err := Do[server.ItemsResponse[secrets.Secrets]](stub, req, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	want := server.ItemsResponse[secrets.Secrets]{Items: secrets.Secrets{"s1": {Id: "s1", Version: 1}}}
	if !cmp.Equal(got, want, cmpSecretOpts) {
		t.Errorf("Do response:\n%s", cmp.Diff(want, got, cmpSecretOpts))
	}
}

func TestDo_clientError(t *testing.T) {
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/secrets", nil)
	stub := &stubClient{doErr: io.ErrUnexpectedEOF}
	got, err := Do[secrets.Secrets](stub, req, nil)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("err = %v", err)
	}
	if got != nil {
		t.Errorf("expected nil body on error, got %v", got)
	}
}

func TestDo_serverErrorResponse(t *testing.T) {
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/secrets", nil)
	stub := &stubClient{status: 200, body: `{"error":{"status":400,"message":"bad request"}}`}
	got, err := Do[secrets.Secrets](stub, req, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got != nil {
		t.Errorf("expected nil body, got %v", got)
	}
	if respErr, ok := err.(*server.ErrorResponse); !ok || respErr.HttpError == nil || respErr.HttpError.Code != 400 {
		t.Errorf("error = %v", err)
	}
}

func TestDo_nonJSONErrorResponse(t *testing.T) {
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/secrets", nil)
	stub := &stubClient{status: 404, body: "404 page not found\n"}
	got, err := Do[secrets.Secrets](stub, req, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if got != nil {
		t.Errorf("expected nil body, got %v", got)
	}
	respErr, ok := err.(*server.ErrorResponse)
	if !ok || respErr.HttpError == nil || respErr.HttpError.Code != 404 {
		t.Fatalf("error = %v", err)
	}
}

func TestSecretClient_List(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"items":[{"id":"x","version":1}]}`}
	c := &SecretClient{client: stub}
	got, err := c.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := requestString(stub.lastReq.Load()); got != "GET /secrets\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /secrets\n", got))
	}
	want := secrets.Secrets{"x": {Id: "x", Version: 1}}
	if !cmp.Equal(got, want, cmpSecretOpts) {
		t.Errorf("List response:\n%s", cmp.Diff(want, got, cmpSecretOpts))
	}
}

func TestSecretClient_Get(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"my-secret","version":1}`}
	c := &SecretClient{client: stub}
	got, err := c.Get(ctx, "my-secret")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotReq := requestString(stub.lastReq.Load()); gotReq != "GET /secrets/my-secret\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /secrets/my-secret\n", gotReq))
	}
	want := &secrets.Secret{Id: "my-secret", Version: 1}
	if !cmp.Equal(got, want, cmpSecretOpts) {
		t.Errorf("Get response:\n%s", cmp.Diff(want, got, cmpSecretOpts))
	}
}

func TestInstanceClient_List(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"items":[]}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	got, err := c.List(ctx, 0, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if gotReq := requestString(stub.lastReq.Load()); gotReq != "GET /secrets/sid/instances\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /secrets/sid/instances\n", gotReq))
	}
	want := secrets.Instances{}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("List response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Get(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	got, err := c.Get(ctx, "i1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotReq := requestString(stub.lastReq.Load()); gotReq != "GET /secrets/sid/instances/i1\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /secrets/sid/instances/i1\n", gotReq))
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Get response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Create(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"new-id","secret":{"id":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "test", StartedBy: "user"}
	started, err := c.Create(ctx, params, command.Stdio{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	want := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(started, want, cmpInstanceOpts) {
		t.Errorf("Create returned instance:\n%s", cmp.Diff(want, started, cmpInstanceOpts))
	}
	wantReq := "POST /secrets/sid/instances\n" + `{"env":null,"forced":false,"reason":"test"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
}

func TestInstanceClient_Create_hasNoInputField(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"new-id","secret":{"id":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "test", StartedBy: "user"}
	_, err := c.Create(ctx, params, command.Stdio{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	req := stub.lastReq.Load()
	if req == nil {
		t.Fatal("no request recorded")
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "input") {
		t.Fatalf("create POST body must not include input; got %s", body)
	}
}

func TestSecretClient_History(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `[]`}
	c := &SecretClient{client: stub}
	got, err := c.History(ctx, "sid", 0, 10)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	wantReq := "GET /secrets/sid/operations?from=0&to=10\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := []*secrets.Operation{}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("History response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_GetActive(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"active-id","secret":{"id":"s1","version":1},"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	got, err := c.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	wantReq := "GET /secrets/sid/active\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := &secrets.Instance{Id: "active-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("GetActive response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Destroy(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"id":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "r", StartedBy: "user"}
	started, err := c.Destroy(ctx, "i1", params, discardStdio())
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(started, want, cmpInstanceOpts) {
		t.Errorf("Destroy returned instance:\n%s", cmp.Diff(want, started, cmpInstanceOpts))
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"destroy","env":null,"forced":false,"reason":"r"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
}

func discardStdio() command.Stdio {
	return command.Stdio{Stdout: io.Discard, Stderr: io.Discard}
}

func TestInstanceClient_Activate(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"id":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "activate-reason", StartedBy: "user"}
	started, err := c.Activate(ctx, "i1", params, discardStdio())
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(started, want, cmpInstanceOpts) {
		t.Errorf("Activate returned instance:\n%s", cmp.Diff(want, started, cmpInstanceOpts))
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"activate","env":null,"forced":false,"reason":"activate-reason"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
}

func TestInstanceClient_Deactivate(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"id":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "deact", StartedBy: "user"}
	started, err := c.Deactivate(ctx, "i1", params, discardStdio())
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(started, want, cmpInstanceOpts) {
		t.Errorf("Deactivate returned instance:\n%s", cmp.Diff(want, started, cmpInstanceOpts))
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"deactivate","env":null,"forced":false,"reason":"deact"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
}

func TestInstanceClient_Await_retriesUntilComplete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stub := &resultRetryStub{}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	ops := &OperationsClient{parent: c, instanceId: "i1"}

	_, got, err := ops.Await(ctx, 1)
	if err != nil {
		t.Fatalf("Await: %v", err)
	}
	if got.Id != "i1" {
		t.Fatalf("instance id = %q", got.Id)
	}
	if stub.resultCalls.Load() < 2 {
		t.Fatalf("result calls = %d, want at least 2", stub.resultCalls.Load())
	}
}

type resultRetryStub struct {
	resultCalls atomic.Int32
}

func (s *resultRetryStub) Do(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "/result") {
		if s.resultCalls.Add(1) == 1 {
			return &http.Response{
				StatusCode: 408,
				Body:       io.NopCloser(bytes.NewReader([]byte(`{"error":{"status":408,"message":"timeout"}}`))),
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"id":"i1","secret":{"id":"s1","version":1},"operationNumber":1,"status":{}}`))),
		}, nil
	}
	return nil, fmt.Errorf("stub: unexpected request %s %s", req.Method, req.URL.Path)
}

func TestInstanceClient_Test(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"id":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "test-run", StartedBy: "user"}
	started, err := c.Test(ctx, "i1", params, discardStdio())
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(started, want, cmpInstanceOpts) {
		t.Errorf("Test returned instance:\n%s", cmp.Diff(want, started, cmpInstanceOpts))
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"test","env":null,"forced":false,"reason":"test-run"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
}

func TestInstanceClient_History(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `[]`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	ops := &OperationsClient{parent: c, instanceId: "i1"}
	got, err := ops.List(ctx, 5, 15)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	wantReq := "GET /secrets/sid/instances/i1/operations?from=5&to=15\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := []*secrets.Operation{}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("History response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}
