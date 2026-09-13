package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var cmpSecretOpts = cmp.Options{
	cmpopts.IgnoreUnexported(secrets.Secret{}, command.Command{}),
}
var cmpInstanceOpts = cmp.Options{
	cmpopts.IgnoreUnexported(secrets.Secret{}, command.Command{}),
	cmpopts.IgnoreUnexported(time.Time{}),
}

type stubClient struct {
	status  int
	body    string
	doErr   error
	lastReq atomic.Pointer[http.Request]
}

func (s *stubClient) Do(req *http.Request) (*http.Response, error) {
	if !s.lastReq.CompareAndSwap(nil, req) {
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

type recordingClient struct {
	mu       sync.Mutex
	requests []string
	handler  func(req *http.Request) (*http.Response, error)
}

func (r *recordingClient) Do(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(body))
	r.mu.Lock()
	r.requests = append(r.requests, req.Method+" "+req.URL.RequestURI()+"\n"+string(body))
	handler := r.handler
	r.mu.Unlock()
	if handler != nil {
		return handler(req)
	}
	return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewReader(nil))}, nil
}

func (r *recordingClient) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.requests))
	copy(out, r.requests)
	return out
}

func requestString(req *http.Request) string {
	if req == nil {
		return ""
	}
	body, _ := io.ReadAll(req.Body)
	return req.Method + " " + req.URL.RequestURI() + "\n" + string(body)
}

func ptr[T any](v T) *T { return &v }

func TestBuildRequest(t *testing.T) {
	ctx := context.Background()
	t.Run("no body", func(t *testing.T) {
		req, err := (&SecretClient{}).buildRequest(ctx, http.MethodGet, "/secrets", nil)
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
		body := server.SecretOperationRequest{
			SecretId: "s1",
			OperationRequest: server.OperationRequest{
				Reason: "create",
			},
		}
		req, err := (&SecretClient{}).buildRequest(ctx, http.MethodPost, "/instances", body)
		if err != nil {
			t.Fatal(err)
		}
		got := requestString(req)
		want := "POST /instances\n" + `{"secretId":"s1","env":null,"forced":false,"reason":"create"}` + "\n"
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

func TestCatalog_SecretsList(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"items":[{"id":"x","version":1}]}`}
	c := &SecretClient{client: stub}
	got, err := c.Catalog().Secrets().List(ctx)
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

func TestCatalog_SecretsGet(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"my-secret","version":1}`}
	c := &SecretClient{client: stub}
	got, err := c.Catalog().Secrets().Get(ctx, "my-secret")
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

func TestCatalog_InstancesList(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"items":[]}`}
	c := &SecretClient{client: stub}
	got, err := c.Catalog().Instances().List(ctx, ptr("sid"), 0, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantReq := "GET /instances?from=0&secretId=sid&to=10\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := secrets.Instances{}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("List response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestCatalog_InstancesGet(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`}
	c := &SecretClient{client: stub}
	got, err := c.Catalog().Instances().Get(ctx, "i1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotReq := requestString(stub.lastReq.Load()); gotReq != "GET /instances/i1\n" {
		t.Errorf("request:\n%s", cmp.Diff("GET /instances/i1\n", gotReq))
	}
	want := &secrets.Instance{Id: "i1", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("Get response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestCatalog_GetActive(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"id":"active-id","secret":{"id":"s1","version":1},"status":{}}`}
	c := &SecretClient{client: stub}
	got, err := c.Catalog().Instances().GetActive(ctx, "sid")
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

func TestCatalog_OperationsList(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `[]`}
	c := &SecretClient{client: stub}
	got, err := c.Catalog().Operations().List(ctx, ptr("sid"), ptr("i1"), 5, 15)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantReq := "GET /operations?from=5&instanceId=i1&secretId=sid&to=15\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
	want := []*secrets.Operation{}
	if !cmp.Equal(got, want, cmpInstanceOpts) {
		t.Errorf("List response:\n%s", cmp.Diff(want, got, cmpInstanceOpts))
	}
}

func TestCatalog_OperationsList_unfiltered(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `[]`}
	c := &SecretClient{client: stub}
	_, err := c.Catalog().Operations().List(ctx, nil, nil, 0, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantReq := "GET /operations?from=0&to=10\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
}

func TestCatalog_InstancesList_unfiltered(t *testing.T) {
	ctx := context.Background()
	stub := &stubClient{status: 200, body: `{"items":[]}`}
	c := &SecretClient{client: stub}
	_, err := c.Catalog().Instances().List(ctx, nil, 0, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantReq := "GET /instances?from=0&to=10\n"
	if gotReq := requestString(stub.lastReq.Load()); gotReq != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gotReq))
	}
}

func holdAttach(t *testing.T) func(context.Context, string) (io.ReadWriteCloser, error) {
	t.Helper()
	return func(_ context.Context, _ string) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	}
}

func TestRunner_Create_attachesBeforePOST(t *testing.T) {
	ctx := context.Background()
	var attached atomic.Int32
	rec := &recordingClient{handler: func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			if attached.Load() != 3 {
				t.Errorf("POST with %d attaches, want 3", attached.Load())
			}
			if req.URL.Path != "/instances" {
				t.Errorf("path = %s", req.URL.Path)
			}
		}
		return jsonResponse(200, `{"id":"new-id","secret":{"id":"s1","version":1},"status":{}}`), nil
	}}
	c := &SecretClient{client: rec, attach: func(ctx context.Context, path string) (io.ReadWriteCloser, error) {
		if !strings.Contains(path, "/secrets/sid/attach/") {
			t.Errorf("attach path = %s", path)
		}
		attached.Add(1)
		return holdAttach(t)(ctx, path)
	}}
	params := executor.OperationParameters{Reason: "test", StartedBy: "user"}
	started, handle, err := c.Runner("sid").Run(ctx, secrets.Create, "", params, nil, command.Stdio{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = handle.Cancel(context.Background()) })
	want := &secrets.Instance{Id: "new-id", Secret: secrets.Secret{Id: "s1", Version: 1}, Status: secrets.Status{}}
	if !cmp.Equal(started, want, cmpInstanceOpts) {
		t.Errorf("Run returned instance:\n%s", cmp.Diff(want, started, cmpInstanceOpts))
	}
	gots := rec.got()
	if len(gots) < 1 {
		t.Fatal("no requests")
	}
	wantReq := "POST /instances\n" + `{"secretId":"sid","env":null,"forced":false,"reason":"test"}` + "\n"
	if gots[0] != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, gots[0]))
	}
	if attached.Load() != 3 {
		t.Fatalf("attaches = %d, want 3", attached.Load())
	}
}

func TestRunner_Create_POSTBodyHasNoInput(t *testing.T) {
	ctx := context.Background()
	rec := &recordingClient{handler: func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, `{"id":"new-id","secret":{"id":"s1","version":1},"status":{}}`), nil
	}}
	c := &SecretClient{client: rec, attach: holdAttach(t)}
	_, handle, err := c.Runner("sid").Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "test"}, nil, command.Stdio{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = handle.Cancel(context.Background()) })
	if strings.Contains(rec.got()[0], "input") {
		t.Fatalf("create POST body must not include input; got %s", rec.got()[0])
	}
}

func TestRunner_NamedOperation(t *testing.T) {
	ctx := context.Background()
	rec := &recordingClient{handler: func(*http.Request) (*http.Response, error) {
		return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`), nil
	}}
	c := &SecretClient{client: rec, attach: holdAttach(t)}
	params := executor.OperationParameters{Reason: "activate-reason", StartedBy: "user"}
	_, handle, err := c.Runner("sid").Run(ctx, secrets.Activate, "i1", params, nil, command.Stdio{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = handle.Cancel(context.Background()) })
	wantReq := "POST /operations\n" + `{"instanceId":"i1","name":"activate","env":null,"forced":false,"reason":"activate-reason"}` + "\n"
	if rec.got()[0] != wantReq {
		t.Errorf("request:\n%s", cmp.Diff(wantReq, rec.got()[0]))
	}
}

func TestRunner_Wait_getsInstanceAfterPumps(t *testing.T) {
	ctx := context.Background()
	peers := map[string]net.Conn{}
	var peersMu sync.Mutex
	rec := &recordingClient{handler: func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost:
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`), nil
		case strings.HasSuffix(req.URL.Path, "/instances/i1"):
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{"completedAt":"2024-01-01T00:00:00Z"}}`), nil
		default:
			return jsonResponse(500, `{"error":{"status":500,"message":"`+req.URL.Path+`"}}`), nil
		}
	}}
	c := &SecretClient{client: rec, attach: func(_ context.Context, path string) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		peersMu.Lock()
		peers[path] = b
		peersMu.Unlock()
		t.Cleanup(func() {
			_ = a.Close()
			_ = b.Close()
		})
		return a, nil
	}}

	_, handle, err := c.Runner("sid").Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r"}, nil, command.Stdio{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	waitCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_, err = handle.Wait(waitCtx)
	cancel()
	if err == nil {
		t.Fatal("Wait returned before pumps finished")
	}

	peersMu.Lock()
	for _, p := range peers {
		_ = p.Close()
	}
	peersMu.Unlock()

	final, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if final.Id != "i1" || final.Status.CompletedAt == nil {
		t.Fatalf("final = %+v", final)
	}
}

func TestRunner_Wait_successWithoutCancel(t *testing.T) {
	ctx := context.Background()
	var stdoutBuf bytes.Buffer
	attachPeers := map[string]net.Conn{}

	rec := &recordingClient{handler: func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost:
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`), nil
		case req.URL.Path == "/instances/i1":
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{"completedAt":"2024-01-01T00:00:00Z"}}`), nil
		default:
			return jsonResponse(500, `{"error":{"status":500,"message":"unexpected"}}`), fmt.Errorf("unexpected %s %s", req.Method, req.URL.Path)
		}
	}}
	c := &SecretClient{client: rec, attach: func(_ context.Context, path string) (io.ReadWriteCloser, error) {
		client, server := net.Pipe()
		attachPeers[path] = server
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}}

	_, handle, err := c.Runner("sid").Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r"}, nil, command.Stdio{
		Stdin:  strings.NewReader("hello-in"),
		Stdout: &stdoutBuf,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	stdinPeer := attachPeers["/secrets/sid/attach/stdin"]
	stdoutPeer := attachPeers["/secrets/sid/attach/stdout"]
	stderrPeer := attachPeers["/secrets/sid/attach/stderr"]
	if stdinPeer == nil || stdoutPeer == nil || stderrPeer == nil {
		t.Fatal("missing attach peer")
	}
	go func() { _, _ = io.Copy(io.Discard, stdinPeer) }()
	if _, err := stdoutPeer.Write([]byte("hello-out")); err != nil {
		t.Fatalf("write stdout peer: %v", err)
	}
	_ = stdoutPeer.Close()
	_ = stderrPeer.Close()

	final, err := handle.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if final.Status.CompletedAt == nil {
		t.Fatalf("final = %+v, want completedAt", final)
	}
	if stdoutBuf.String() != "hello-out" {
		t.Fatalf("stdout = %q", stdoutBuf.String())
	}
}

func TestRunner_Wait_finishesIfStdinRemainsOpen(t *testing.T) {
	ctx := context.Background()
	stdinR, stdinW := io.Pipe()
	t.Cleanup(func() {
		_ = stdinR.Close()
		_ = stdinW.Close()
	})
	attachPeers := map[string]net.Conn{}

	rec := &recordingClient{handler: func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPost:
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`), nil
		case req.URL.Path == "/instances/i1":
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{"completedAt":"2024-01-01T00:00:00Z"}}`), nil
		default:
			return jsonResponse(500, `{"error":{"status":500,"message":"unexpected"}}`), fmt.Errorf("unexpected %s %s", req.Method, req.URL.Path)
		}
	}}
	c := &SecretClient{client: rec, attach: func(_ context.Context, path string) (io.ReadWriteCloser, error) {
		client, server := net.Pipe()
		attachPeers[path] = server
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		return client, nil
	}}

	_, handle, err := c.Runner("sid").Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r"}, nil, command.Stdio{
		Stdin:  stdinR,
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	stdoutPeer := attachPeers["/secrets/sid/attach/stdout"]
	stderrPeer := attachPeers["/secrets/sid/attach/stderr"]
	if stdoutPeer == nil || stderrPeer == nil || attachPeers["/secrets/sid/attach/stdin"] == nil {
		t.Fatal("missing attach peer")
	}
	_ = stdoutPeer.Close()
	_ = stderrPeer.Close()

	waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	final, err := handle.Wait(waitCtx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if final.Status.CompletedAt == nil {
		t.Fatalf("final = %+v", final)
	}
}

func TestRunner_closesAttachOnPOSTFailure(t *testing.T) {
	ctx := context.Background()
	stdinClient, stdinServer := net.Pipe()
	t.Cleanup(func() { _ = stdinServer.Close() })

	attachN := 0
	c := &SecretClient{
		client: &recordingClient{handler: func(*http.Request) (*http.Response, error) {
			return jsonResponse(400, `{"error":{"status":400,"message":"bad"}}`), nil
		}},
		attach: func(_ context.Context, path string) (io.ReadWriteCloser, error) {
			attachN++
			if strings.HasSuffix(path, "/stdin") {
				return stdinClient, nil
			}
			a, b := net.Pipe()
			t.Cleanup(func() {
				_ = a.Close()
				_ = b.Close()
			})
			return a, nil
		},
	}

	_, _, err := c.Runner("sid").Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r"}, nil, command.Stdio{})
	if err == nil {
		t.Fatal("want POST error")
	}
	if attachN != 3 {
		t.Fatalf("attaches = %d, want 3 before failed POST", attachN)
	}

	buf := make([]byte, 1)
	_, readErr := stdinServer.Read(buf)
	if readErr != io.EOF {
		t.Fatalf("stdin server read = %v, want EOF after Run cleanup", readErr)
	}
}

func TestRunner_Wait_notCompleted(t *testing.T) {
	ctx := context.Background()
	rec := &recordingClient{handler: func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`), nil
		}
		return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{"startedAt":"2024-01-01T00:00:00Z"}}`), nil
	}}
	c := &SecretClient{client: rec, attach: holdAttach(t)}
	_, handle, err := c.Runner("sid").Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r"}, nil, command.Stdio{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := handle.Cancel(ctx); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	_, err = handle.Wait(ctx)
	if err == nil || !strings.Contains(err.Error(), "not completed") {
		t.Fatalf("Wait = %v, want not completed error", err)
	}
}

func TestRunner_Wait_failedAt(t *testing.T) {
	ctx := context.Background()
	rec := &recordingClient{handler: func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{}}`), nil
		}
		return jsonResponse(200, `{"id":"i1","secret":{"id":"s1","version":1},"status":{"failedAt":"2024-01-01T00:00:00Z"}}`), nil
	}}
	c := &SecretClient{client: rec, attach: holdAttach(t)}
	_, handle, err := c.Runner("sid").Run(ctx, secrets.Create, "", executor.OperationParameters{Reason: "r"}, nil, command.Stdio{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := handle.Cancel(ctx); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	final, err := handle.Wait(ctx)
	if err == nil {
		t.Fatal("Wait = nil, want failed error")
	}
	if final == nil || final.Status.FailedAt == nil {
		t.Fatal("expected failedAt")
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
}

var _ backend.Backend = (*SecretClient)(nil)
