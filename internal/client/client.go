package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

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

func (c *SecretClient) Instances(secretId string) *InstanceClient {
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
	go c.runStdioExchange(ctx, instance, stdio)
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
	go c.runStdioExchange(ctx, instance, stdio)
	return instance, nil
}

// runStdioExchange streams stdin to the server and copies stdout/stderr back
// via POST .../operations/{opNumber}/process/io. The loop ends when server stdout
// and stderr are complete (subprocess exited), matching normal pipe behaviour:
// an open stdin at the client does not keep output streaming after the process ends.
func (c *InstanceClient) runStdioExchange(ctx context.Context, instance *secrets.Instance, stdio command.Stdio) {
	if stdio.Stdin == nil && stdio.Stdout == nil && stdio.Stderr == nil {
		return
	}

	path := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d/process/io",
		c.secretId, instance.Id, instance.Status.OperationNumber)

	stdinCh := make(chan []byte, 8)
	if stdio.Stdin != nil {
		go func() {
			defer close(stdinCh)
			buf := make([]byte, 4096)
			for {
				n, err := stdio.Stdin.Read(buf)
				if n > 0 {
					chunk := make([]byte, n)
					copy(chunk, buf[:n])
					stdinCh <- chunk
				}
				if err != nil {
					return
				}
			}
		}()
	}

	stdinCompleteSent := false
	stdinTo := 0
	stdoutFrom := 0
	stderrFrom := 0
	stdoutDone := false
	stderrDone := false

	for !stdoutDone || !stderrDone {
		if ctx.Err() != nil {
			return
		}

		reqBody := server.ExchangeIORequest{}
		if !stdoutDone {
			reqBody.Stdout = &server.ExchangeIndex{Index: int64(stdoutFrom)}
		}
		if !stderrDone {
			reqBody.Stderr = &server.ExchangeIndex{Index: int64(stderrFrom)}
		}

		if !stdinCompleteSent {
			select {
			case chunk, ok := <-stdinCh:
				if ok {
					reqBody.Stdin = &server.ExchangeBytes{
						Index: int64(stdinTo),
						Bytes: chunk,
					}
				} else {
					reqBody.Stdin = &server.ExchangeBytes{
						Index:  int64(stdinTo),
						Closed: true,
					}
					stdinCompleteSent = true
				}
			default:
			}
		}

		req, err := BuildRequest(ctx, http.MethodPost, path, reqBody)
		if err != nil {
			return
		}
		query := req.URL.Query()
		query.Set("maxWait", "5s")
		req.URL.RawQuery = query.Encode()

		resp, err := Do[server.ExchangeIOResponse](c.parent.client, req, err)
		if err != nil {
			return
		}

		if resp.Stdin != nil {
			stdinTo = int(resp.Stdin.Index)
		}

		if resp.Stdout != nil {
			if len(resp.Stdout.Bytes) > 0 && stdio.Stdout != nil {
				stdio.Stdout.Write(resp.Stdout.Bytes)
				stdoutFrom += len(resp.Stdout.Bytes)
			}
			if resp.Stdout.Closed {
				stdoutDone = true
			}
		}

		if resp.Stderr != nil {
			if len(resp.Stderr.Bytes) > 0 && stdio.Stderr != nil {
				stdio.Stderr.Write(resp.Stderr.Bytes)
				stderrFrom += len(resp.Stderr.Bytes)
			}
			if resp.Stderr.Closed {
				stderrDone = true
			}
		}
	}
}

func (c *InstanceClient) Await(ctx context.Context, instanceId string, operationNumber int) (*secrets.Instance, error) {
	maxWait := server.DefaultMaxPollDuration
	path := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d/result",
		c.secretId, instanceId, operationNumber)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req, err := BuildRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		query := req.URL.Query()
		query.Set("maxWait", maxWait.String())
		req.URL.RawQuery = query.Encode()
		instance, err := Do[*secrets.Instance](c.parent.client, req, nil)
		if err == nil {
			return instance, nil
		}
		var resp *server.ErrorResponse
		if errors.As(err, &resp) && resp.HttpError != nil && resp.HttpError.Code == http.StatusRequestTimeout {
			continue
		}
		return nil, err
	}
}

func (c *InstanceClient) Cancel(ctx context.Context, instanceId string, operationNumber int) error {
	path := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d/cancel",
		c.secretId, instanceId, operationNumber)
	req, err := BuildRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.parent.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var errorResponse server.ErrorResponse
		if json.Unmarshal(bodyBytes, &errorResponse) == nil && errorResponse.HttpError != nil {
			return &errorResponse
		}
		return server.NewErrorResponse(resp.StatusCode, nil)
	}
	return nil
}

func (c *InstanceClient) History(ctx context.Context, instanceId string, from int, to int) (operations []*secrets.Operation, err error) {
	req, err := BuildRequest(ctx, http.MethodGet, "/secrets/"+c.secretId+"/instances/"+instanceId+"/operations", nil)
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secrets.Operation](c.parent.client, req, err)
}

var _ store.Instances = (*InstanceClient)(nil)
