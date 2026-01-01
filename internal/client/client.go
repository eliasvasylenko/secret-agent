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

	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

type SecretClient struct {
	socket string
	client http.Client
}

type InstanceClient struct {
	socket   string
	client   http.Client
	secretId string
}

func NewSecretStore(socket string) *SecretClient {
	client := http.Client{
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

func Do[T any](client http.Client, req *http.Request, err error) (T, error) {
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
		socket:   c.socket,
		client:   c.client,
		secretId: secretId,
	}
}

func (c *InstanceClient) List(ctx context.Context, from int, to int) (secrets.Instances, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances", nil)
	items, err := Do[server.ItemsResponse[secrets.Instances]](c.client, req, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

func (c *InstanceClient) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId, nil)
	return Do[*secrets.Instance](c.client, req, err)
}

func (c *InstanceClient) GetActive(ctx context.Context) (*secrets.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/active", nil)
	return Do[*secrets.Instance](c.client, req, err)
}

func (c *InstanceClient) Create(ctx context.Context, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	instance := server.OperationCreate{
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances", instance)
	return Do[*secrets.Instance](c.client, req, err)
}

func (c *InstanceClient) Destroy(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	instance := server.OperationCreate{
		Name:                secrets.Destroy,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secrets.Instance](c.client, req, err)
}

func (c *InstanceClient) Activate(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	instance := server.OperationCreate{
		Name:                secrets.Activate,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secrets.Instance](c.client, req, err)
}

func (c *InstanceClient) Deactivate(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	instance := server.OperationCreate{
		Name:                secrets.Deactivate,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secrets.Instance](c.client, req, err)
}

func (c *InstanceClient) Test(ctx context.Context, instanceId string, parameters secrets.OperationParameters) (*secrets.Instance, error) {
	instance := server.OperationCreate{
		Name:                secrets.Test,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secrets.Instance](c.client, req, err)
}

func (c *InstanceClient) History(ctx context.Context, instanceId string, from int, to int) (operations []*secrets.Operation, err error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", nil)
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secrets.Operation](c.client, req, err)
}
