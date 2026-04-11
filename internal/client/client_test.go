package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// cmp options for comparing secrets types that contain unexported fields.
var cmpSecretOpts = cmp.Options{
	cmpopts.IgnoreUnexported(secrets.Secret{}, command.Command{}),
}
var cmpInstanceOpts = cmp.Options{
	cmpopts.IgnoreUnexported(secrets.Secret{}, command.Command{}),
	cmpopts.IgnoreUnexported(time.Time{}),
}

// stubClient implements httpClient. It records the first request for assertion
// and returns an error for any subsequent calls, which causes poll goroutines
// spawned by startPolling to exit immediately.
type stubClient struct {
	status  int
	body    string
	doErr   error
	lastReq atomic.Pointer[http.Request]
}

func (s *stubClient) Do(req *http.Request) (*http.Response, error) {
	first := s.lastReq.CompareAndSwap(nil, req)
	if !first {
		return nil, fmt.Errorf("stub: unexpected request")
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
	stub := &stubClient{status: 200, body: `{"items":[{"name":"s1","version":1}]}`}
	got, err := Do[server.ItemsResponse[secrets.Secrets]](stub, req, nil)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	want := server.ItemsResponse[secrets.Secrets]{Items: secrets.Secrets{"s1": {Name: "s1", Version: 1}}}
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

func TestSecretClient_List(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"items":[{"name":"x","version":1}]}`}
	c := &SecretClient{client: stub}
	got, err := c.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got := requestString(stub.lastReq.Load()); got != "GET /secrets\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /secrets\n", got))
	}
	want := secrets.Secrets{"x": {Name: "x", Version: 1}}
	if !cmp.Equal(got, want, cmpSecretOpts) {
		t.Errorf("List response:\n%s", cmp.Diff(want, got, cmpSecretOpts))
	}
}

func TestSecretClient_Get(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"name":"my-secret","version":1}`}
	c := &SecretClient{client: stub}
	got, err := c.Get(ctx, "my-secret")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotReq := requestString(stub.lastReq.Load()); gotReq != "GET /secrets/my-secret\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /secrets/my-secret\n", gotReq))
	}
	want := &secrets.Secret{Name: "my-secret", Version: 1}
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
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"name":"s1","version":1},"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	got, err := c.Get(ctx, "i1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotReq := requestString(stub.lastReq.Load()); gotReq != "GET /secrets/sid/instances/i1\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /secrets/sid/instances/i1\n", gotReq))
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Get response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Create(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"new-id","secret":{"name":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "test", StartedBy: "user"}
	got, err := c.Create(ctx, params, command.Stdio{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	wantReq := "POST /secrets/sid/instances\n" + `{"name":"","env":null,"forced":false,"reason":"test"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Create response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Create_PostJSON_decodesInput(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"new-id","secret":{"name":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "test", StartedBy: "user"}
	_, err := c.Create(ctx, params, command.Stdio{Stdin: "hello\n", Stdout: io.Discard, Stderr: io.Discard})
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
	var decoded server.OperationParameters
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal POST body: %v\n%s", err, body)
	}
	if decoded.Input != "hello\n" {
		t.Fatalf("JSON input field = %q, want hello\\n", decoded.Input)
	}
}

func TestInstanceClient_Create_withStdin(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"new-id","secret":{"name":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "test", StartedBy: "user"}
	got, err := c.Create(ctx, params, command.Stdio{Stdin: "hello\n", Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	wantReq := "POST /secrets/sid/instances\n" + `{"name":"","env":null,"forced":false,"reason":"test","input":"hello\n"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Create response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
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
	stub := &stubClient{status: 200, body: `{"id":"active-id","secret":{"name":"s1","version":1},"status":{}}`}
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
	want := &secrets.Instance{Id: "active-id", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("GetActive response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Destroy(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"name":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "r", StartedBy: "user"}
	got, err := c.Destroy(ctx, "i1", params, command.Stdio{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"destroy","env":null,"forced":false,"reason":"r"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Destroy response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Activate(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"name":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "activate-reason", StartedBy: "user"}
	got, err := c.Activate(ctx, "i1", params, command.Stdio{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"activate","env":null,"forced":false,"reason":"activate-reason"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Activate response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Deactivate(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"name":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "deact", StartedBy: "user"}
	got, err := c.Deactivate(ctx, "i1", params, command.Stdio{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"deactivate","env":null,"forced":false,"reason":"deact"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Deactivate response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_Test(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"name":"s1","version":1},"operationNumber":1,"status":{}}`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	params := executor.OperationParameters{Reason: "test-run", StartedBy: "user"}
	got, err := c.Test(ctx, "i1", params, command.Stdio{Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	wantReq := "POST /secrets/sid/instances/i1/operations\n" + `{"name":"test","env":null,"forced":false,"reason":"test-run"}` + "\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Name: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Test response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestInstanceClient_History(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `[]`}
	parent := &SecretClient{client: stub}
	c := &InstanceClient{parent: parent, secretId: "sid"}
	got, err := c.History(ctx, "i1", 5, 15)
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
