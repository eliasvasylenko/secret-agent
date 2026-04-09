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
	polls    sync.Map
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewSecretStore(socket string) *SecretClient {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
	return &SecretClient{
		socket: socket,
		client: client,
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
	items, err := Do[server.ItemsResponse[secrets.Secrets]](c.client, req, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

func (c *SecretClient) Get(ctx context.Context, secretId string) (*secrets.Secret, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+secretId, nil)
	return Do[*secrets.Secret](c.client, req, err)
}

func (c *SecretClient) History(ctx context.Context, secretId string, from int, to int) (operations []*secrets.Operation, err error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+secretId+"/operations", nil)
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secrets.Operation](c.client, req, err)
}

func (c *SecretClient) Instances(secretId string) *InstanceClient {
	return &InstanceClient{
		parent:   c,
		secretId: secretId,
	}
}

func (c *InstanceClient) List(ctx context.Context, from int, to int) (secrets.Instances, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances", nil)
	items, err := Do[server.ItemsResponse[secrets.Instances]](c.parent.client, req, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

func (c *InstanceClient) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId, nil)
	return Do[*secrets.Instance](c.parent.client, req, err)
}

func (c *InstanceClient) GetActive(ctx context.Context) (*secrets.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/active", nil)
	return Do[*secrets.Instance](c.parent.client, req, err)
}

func (c *InstanceClient) Create(ctx context.Context, parameters executor.OperationParameters, stdio command.Stdio) (*secrets.Instance, error) {
	body := server.CreateOperationParameters{
		OperationParameters: server.OperationParameters{
			Env:    parameters.Env,
			Forced: parameters.Forced,
			Reason: parameters.Reason,
			Input:  stdio.Stdin,
		},
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances", body)
	instance, err := Do[*secrets.Instance](c.parent.client, req, err)
	if err != nil {
		return nil, err
	}
	c.startPolling(instance, stdio.Stdout, stdio.Stderr)
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
			Input:  stdio.Stdin,
		},
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", body)
	instance, err := Do[*secrets.Instance](c.parent.client, req, err)
	if err != nil {
		return nil, err
	}
	c.startPolling(instance, stdio.Stdout, stdio.Stderr)
	return instance, nil
}

// startPolling spawns goroutines to poll stdout and stderr for an operation,
// and a cleanup goroutine that removes the WaitGroup from the map once both finish.
func (c *InstanceClient) startPolling(instance *secrets.Instance, stdout, stderr io.Writer) {
	opNumber := instance.Status.OperationNumber
	wg := &sync.WaitGroup{}
	c.polls.Store(opNumber, wg)
	wg.Add(2)
	go c.poll(wg, instance, stdout, "stdout")
	go c.poll(wg, instance, stderr, "stderr")
	go func() {
		wg.Wait()
		c.polls.Delete(opNumber)
	}()
}

// poll polls a stream endpoint and forwards bytes to the writer until complete.
func (c *InstanceClient) poll(wg *sync.WaitGroup, instance *secrets.Instance, w io.Writer, stream string) {
	defer wg.Done()
	path := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d/%s",
		c.secretId, instance.Id, instance.Status.OperationNumber, stream)
	fromByte := 0
	for {
		req, err := BuildRequest(context.Background(), http.MethodGet, path, nil)
		if err != nil {
			return
		}
		query := req.URL.Query()
		query.Set("fromByte", strconv.Itoa(fromByte))
		query.Set("maxWait", "5s")
		req.URL.RawQuery = query.Encode()

		resp, err := Do[server.StreamResponse](c.parent.client, req, nil)
		if err != nil {
			return
		}

		if len(resp.Data) > 0 {
			w.Write(resp.Data)
			fromByte += len(resp.Data)
		}

		if resp.Complete {
			return
		}
	}
}

func (c *InstanceClient) Await(ctx context.Context, instanceId string, operationNumber int) (*secrets.Instance, error) {
	path := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d/await",
		c.secretId, instanceId, operationNumber)
	req, err := BuildRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	instance, err := Do[*secrets.Instance](c.parent.client, req, nil)
	if err != nil {
		return nil, err
	}
	if instance.Status.OperationNumber < operationNumber {
		return instance, &store.UnknkownOperationError{
			Expected: operationNumber,
			Latest:   instance.Status.OperationNumber,
		}
	}
	if instance.Status.OperationNumber > operationNumber {
		return instance, &store.StaleOperationError{
			Expected: operationNumber,
			Latest:   instance.Status.OperationNumber,
		}
	}
	if wg, ok := c.polls.Load(operationNumber); ok {
		wg.(*sync.WaitGroup).Wait()
	}
	return instance, nil
}

func (c *InstanceClient) History(ctx context.Context, instanceId string, from int, to int) (operations []*secrets.Operation, err error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", nil)
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secrets.Operation](c.parent.client, req, err)
}

var _ store.Instances = (*InstanceClient)(nil)
