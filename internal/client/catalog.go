package client

import (
	"context"
	"net/http"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/secrets"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

type catalog struct {
	client *SecretClient
}

func (c catalog) Secrets() backend.Secrets {
	return secretsCatalog{client: c.client}
}

func (c catalog) Instances() backend.Instances {
	return instancesCatalog{client: c.client}
}

func (c catalog) Operations() backend.Operations {
	return operationsCatalog{client: c.client}
}

type secretsCatalog struct {
	client *SecretClient
}

func (s secretsCatalog) List(ctx context.Context) (secrets.Secrets, error) {
	req, err := s.client.buildRequest(ctx, http.MethodGet, "/secrets", nil)
	items, err := Do[server.ItemsResponse[secrets.Secrets]](s.client.client, req, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

func (s secretsCatalog) Get(ctx context.Context, secretId string) (*secrets.Secret, error) {
	req, err := s.client.buildRequest(ctx, http.MethodGet, "/secrets/"+secretId, nil)
	return Do[*secrets.Secret](s.client.client, req, err)
}

type instancesCatalog struct {
	client *SecretClient
}

func (i instancesCatalog) List(ctx context.Context, secretId *string, from, to int) (secrets.Instances, error) {
	req, err := i.client.buildRequest(ctx, http.MethodGet, "/instances", nil)
	if err != nil {
		return nil, err
	}
	setQuery(req, from, to, filters{"secretId": secretId})
	items, err := Do[server.ItemsResponse[secrets.Instances]](i.client.client, req, err)
	if err != nil {
		return nil, err
	}
	return items.Items, nil
}

func (i instancesCatalog) Get(ctx context.Context, instanceId string) (*secrets.Instance, error) {
	req, err := i.client.buildRequest(ctx, http.MethodGet, "/instances/"+instanceId, nil)
	return Do[*secrets.Instance](i.client.client, req, err)
}

func (i instancesCatalog) GetActive(ctx context.Context, secretId string) (*secrets.Instance, error) {
	req, err := i.client.buildRequest(ctx, http.MethodGet, "/secrets/"+secretId+"/active", nil)
	return Do[*secrets.Instance](i.client.client, req, err)
}

type operationsCatalog struct {
	client *SecretClient
}

func (o operationsCatalog) List(ctx context.Context, secretId, instanceId *string, from, to int) ([]*secrets.Operation, error) {
	req, err := o.client.buildRequest(ctx, http.MethodGet, "/operations", nil)
	if err != nil {
		return nil, err
	}
	setQuery(req, from, to, filters{"secretId": secretId, "instanceId": instanceId})
	return Do[[]*secrets.Operation](o.client.client, req, err)
}

var _ backend.Catalog = catalog{}
var _ backend.Secrets = secretsCatalog{}
var _ backend.Instances = instancesCatalog{}
var _ backend.Operations = operationsCatalog{}
