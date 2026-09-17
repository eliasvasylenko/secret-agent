package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/eliasvasylenko/secret-agent/internal/backend"
	"github.com/eliasvasylenko/secret-agent/internal/server"
)

type SecretClient struct {
	endpoint endpoint
	client   httpClient
	attach   func(ctx context.Context, path string) (io.ReadWriteCloser, error)
}

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// New talks to a secret-agent HTTP API. address is a Unix socket path,
// a unix:// URL, an http:// or https:// URL, or ssh://[user@]host[:port][/socket].
// The ssh URL path is dial-stdio -s only when sshd runs the client-requested
// command; with restrict,command=, socket and -u/-H come from that command.
func New(address string) (*SecretClient, error) {
	ep, err := parseEndpoint(address)
	if err != nil {
		return nil, err
	}
	return &SecretClient{endpoint: ep, client: ep.httpClient()}, nil
}

func (c *SecretClient) Catalog() backend.Catalog {
	return catalog{client: c}
}

func (c *SecretClient) Runner(secretId string) backend.Runner {
	return &httpRunner{client: c, secretId: secretId}
}

func (c *SecretClient) buildRequest(ctx context.Context, method string, path string, body any) (*http.Request, error) {
	buffer := &bytes.Buffer{}
	if body != nil {
		encoder := json.NewEncoder(buffer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(body); err != nil {
			return nil, err
		}
	}
	return http.NewRequestWithContext(ctx, method, c.endpoint.requestURL(path).String(), buffer)
}

func Do[T any](client httpClient, req *http.Request, err error) (T, error) {
	var body T
	if err != nil {
		return body, err
	}
	response, err := client.Do(req)
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

// filters are optional catalog query parameters; nil values are omitted.
type filters map[string]*string

func setQuery(req *http.Request, from, to int, optional filters) {
	query := req.URL.Query()
	for name, value := range optional {
		if value != nil {
			query.Set(name, *value)
		}
	}
	query.Set("from", strconv.FormatInt(int64(from), 10))
	query.Set("to", strconv.FormatInt(int64(to), 10))
	req.URL.RawQuery = query.Encode()
}

var _ backend.Backend = (*SecretClient)(nil)
