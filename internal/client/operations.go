package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/executor"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
	"github.com/eliasvasylenko/secret-agent/internal/backend"
)

type OperationsClient struct {
	parent     *InstanceClient
	instanceId string
}

func (c *InstanceClient) Operations(instanceId string) backend.Operations {
	return &OperationsClient{
		parent:     c,
		instanceId: instanceId,
	}
}

func (c *OperationsClient) List(ctx context.Context, from int, to int) ([]*secrets.Operation, error) {
	path := fmt.Sprintf("/secrets/%s/instances/%s/operations", c.parent.secretId, c.instanceId)
	req, err := BuildRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
	return Do[[]*secrets.Operation](c.parent.parent.client, req, err)
}

func (c *OperationsClient) Process(context.Context, int) (*backend.Process, error) {
	return nil, fmt.Errorf("process attach not implemented")
}

func (c *OperationsClient) Await(ctx context.Context, operationNumber int) (backend.Event, *secrets.Instance, error) {
	maxWait := server.DefaultMaxPollDuration
	path := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d/result",
		c.parent.secretId, c.instanceId, operationNumber)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		req, err := BuildRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, nil, err
		}
		query := req.URL.Query()
		query.Set("maxWait", maxWait.String())
		req.URL.RawQuery = query.Encode()
		instance, err := Do[*secrets.Instance](c.parent.parent.client, req, nil)
		if err == nil {
			event := backend.NewCompletedEvent("", executor.OperationParameters{
				Forced:    instance.Status.Forced,
				Reason:    instance.Status.Reason,
				StartedBy: instance.Status.StartedBy,
			})
			return event, instance, nil
		}
		var resp *server.ErrorResponse
		if errors.As(err, &resp) && resp.HttpError != nil && resp.HttpError.Code == http.StatusRequestTimeout {
			continue
		}
		return nil, nil, err
	}
}

func (c *OperationsClient) Cancel(ctx context.Context, operationNumber int) error {
	path := fmt.Sprintf("/secrets/%s/instances/%s/operations/%d",
		c.parent.secretId, c.instanceId, operationNumber)
	req, err := BuildRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	resp, err := c.parent.parent.client.Do(req)
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

var _ backend.Operations = (*OperationsClient)(nil)
