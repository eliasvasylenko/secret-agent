package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/eliasvasylenko/secret-agent/internal/command"
	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
	"github.com/eliasvasylenko/secret-agent/internal/store"
)

type SecretClient struct {
	socket string
	client httpClient
}

type InstanceClient struct {
	parent   *SecretClient
	secretId string
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewSecretStore(socket string) *SecretClient {
	return &SecretClient{
		socket: socket,
		client: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		}},
	}
}

func BuildRequest(ctx context.Context, method string, path string, body any) (*http.Request, error) {
	buffer := &bytes.Buffer{}
	var err error
	if body != nil {
		encoder := json.NewEncoder(buffer)
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(body)

		if err != nil {
			return nil, err
		}
	}
	return http.NewRequestWithContext(ctx, method, "http://unix"+path, buffer)
}

func Do[T any](client httpClient, req *http.Request, err error) (T, error) {
	response, err := client.Do(req)
	var body T
	if err != nil {
		return body, err
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return body, err
	}

	var errorResponse server.ErrorResponse
	err = json.Unmarshal(bodyBytes, &errorResponse)
	if err == nil && errorResponse.HttpError != nil {
		return body, &errorResponse
	}

	if response.StatusCode >= 300 {
		return body, server.NewErrorResponse(response.StatusCode, nil)
	}

	err = json.Unmarshal(bodyBytes, &body)
	if err != nil {
		err = fmt.Errorf("failed to parse response, %w - '%s'", err, string(bodyBytes))
	}

	return body, err
}

func (c *SecretClient) List(ctx context.Context) (secrets.Secrets, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets", nil)
	if err != nil {
		return nil, err
	}
	items, err := Do[server.ItemsResponse[secrets.Secrets]](c.client, req, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

func (c *SecretClient) Get(ctx context.Context, secretId string) (*secrets.Secret, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+secretId, nil)
	if err != nil {
		return nil, err
	}
	return Do[*secrets.Secret](c.client, req, err)
}

func (c *SecretClient) History(ctx context.Context, secretId string, from int, to int) (operations []*secrets.Operation, err error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+secretId+"/operations", nil)
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secrets.Operation](c.client, req, err)
}

func (c *SecretClient) Instances(secretId string) store.Instances {
	return &InstanceClient{
		parent:   c,
		secretId: secretId,
	}
}

func (c *InstanceClient) List(ctx context.Context, from int, to int) (secrets.Instances, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances", nil)
	if err != nil {
		return nil, err
	}
	items, err := Do[server.ItemsResponse[secrets.Instances]](c.parent.client, req, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

func (c *InstanceClient) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId, nil)
	if err != nil {
		return nil, err
	}
	return Do[*secrets.Instance](c.parent.client, req, err)
}

func (c *InstanceClient) GetActive(ctx context.Context) (*secrets.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/active", nil)
	if err != nil {
		return nil, err
	}
	return Do[*secrets.Instance](c.parent.client, req, err)
}

func (c *InstanceClient) Create(ctx context.Context, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	body := server.OperationParameters{
		Env:    parameters.Env,
		Forced: parameters.Forced,
		Reason: parameters.Reason,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances", body)
	if err != nil {
		return nil, err
	}
	instance, err := Do[*secrets.Instance](c.parent.client, req, err)
	if err != nil {
		return nil, err
	}
	go c.runAttach(ctx, instance, stdio)
	return instance, nil
}

func (c *InstanceClient) Destroy(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return c.startOperation(ctx, instanceId, secrets.Destroy, parameters, stdio)
}

func (c *InstanceClient) Activate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return c.startOperation(ctx, instanceId, secrets.Activate, parameters, stdio)
}

func (c *InstanceClient) Deactivate(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return c.startOperation(ctx, instanceId, secrets.Deactivate, parameters, stdio)
}

func (c *InstanceClient) Test(ctx context.Context, instanceId string, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	return c.startOperation(ctx, instanceId, secrets.Test, parameters, stdio)
}

func (c *InstanceClient) startOperation(ctx context.Context, instanceId string, name secrets.OperationName, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	body := server.CreateOperationParameters{
		Name: name,
		OperationParameters: server.OperationParameters{
			Env:    parameters.Env,
			Forced: parameters.Forced,
			Reason: parameters.Reason,
		},
	}
	path := "/secrets/" + c.secretId + "/instances/" + instanceId + "/operations"
	req, err := BuildRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return nil, err
	}
	instance, err := Do[*secrets.Instance](c.parent.client, req, err)
	if err != nil {
		return nil, err
	}
	go c.runAttach(ctx, instance, stdio)
	return instance, nil
}

func (c *InstanceClient) runAttach(ctx context.Context, instance *secrets.Instance, stdio command.Stdio) {
	base := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d/attach",
		c.secretId, instance.Id, instance.Status.OperationNumber)

	var wg sync.WaitGroup
	attachStream := func(stream string, direction attachDirection, rw io.ReadWriter) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := upgradeAttach(ctx, c.parent.socket, base+"/"+stream)
			if err != nil {
				return
			}
			_ = copyAttach(ctx, conn, direction, rw)
		}()
	}

	attachStream("stdin", attachWrite, newAttachReadWriter(stdio.Stdin, nil))
	attachStream("stdout", attachRead, newAttachReadWriter(nil, stdio.Stdout))
	attachStream("stderr", attachRead, newAttachReadWriter(nil, stdio.Stderr))
	wg.Wait()
}

type attachReadWriter struct {
	r io.Reader
	w io.Writer
}

func newAttachReadWriter(r io.Reader, w io.Writer) io.ReadWriter {
	return attachReadWriter{r: r, w: w}
}

func (rw attachReadWriter) Read(p []byte) (int, error) {
	if rw.r == nil {
		return 0, io.EOF
	}
	return rw.r.Read(p)
}

func (rw attachReadWriter) Write(p []byte) (int, error) {
	if rw.w == nil {
		return len(p), nil
	}
	return rw.w.Write(p)
}

var _ store.Store = (*SecretClient)(nil)
var _ store.Instances = (*InstanceClient)(nil)
