package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/secret"
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
	var bodyBytes []byte
	var err error
	if body != nil {
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	return http.NewRequestWithContext(ctx, method, "http://unix"+path, bytes.NewReader(bodyBytes))
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
	err = json.Unmarshal(bodyBytes, body)
	return body, err
}

func (c *SecretClient) List(ctx context.Context) (secret.Secrets, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets", nil)
	return Do[secret.Secrets](c.client, req, err)
}

func (c *SecretClient) Get(ctx context.Context, secretId string) (*secret.Secret, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+secretId, nil)
	return Do[*secret.Secret](c.client, req, err)
}

func (c *SecretClient) GetActive(ctx context.Context, secretId string) (*secret.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+secretId+"/active", nil)
	return Do[*secret.Instance](c.client, req, err)
}

func (c *SecretClient) History(ctx context.Context, secretId string, from int, to int) (operations []*secret.Operation, err error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+secretId+"/operations", nil)
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secret.Operation](c.client, req, err)
}

func (c *SecretClient) Instances(secretId string) *InstanceClient {
	return &InstanceClient{
		socket:   c.socket,
		client:   c.client,
		secretId: secretId,
	}
}

func (c *InstanceClient) List(ctx context.Context, from int, to int) (secret.Instances, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances", nil)
	return Do[secret.Instances](c.client, req, err)
}

func (c *InstanceClient) Get(ctx context.Context, instanceId string) (*secret.Instance, error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId, nil)
	return Do[*secret.Instance](c.client, req, err)
}

func (c *InstanceClient) Create(ctx context.Context, parameters secret.OperationParameters) (*secret.Instance, error) {
	instance := OperationCreate{
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances", instance)
	return Do[*secret.Instance](c.client, req, err)
}

func (c *InstanceClient) Destroy(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error) {
	instance := OperationCreate{
		Name:                secret.Destroy,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secret.Instance](c.client, req, err)
}

func (c *InstanceClient) Activate(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error) {
	instance := OperationCreate{
		Name:                secret.Activate,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secret.Instance](c.client, req, err)
}

func (c *InstanceClient) Deactivate(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error) {
	instance := OperationCreate{
		Name:                secret.Deactivate,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secret.Instance](c.client, req, err)
}

func (c *InstanceClient) Test(ctx context.Context, instanceId string, parameters secret.OperationParameters) (*secret.Instance, error) {
	instance := OperationCreate{
		Name:                secret.Test,
		OperationParameters: parameters,
	}
	req, err := BuildRequest(ctx, http.MethodPost, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", instance)
	return Do[*secret.Instance](c.client, req, err)
}

func (c *InstanceClient) History(ctx context.Context, instanceId string, from int, to int) (operations []*secret.Operation, err error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", nil)
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secret.Operation](c.client, req, err)
}
